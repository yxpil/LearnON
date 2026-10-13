//! LearnON configuration: Nginx 风格配置的词法器与解析器。
//!
//! 语法示例：
//! ```text
//! listen 8080;
//! server_name localhost;
//!
//! location /api {
//!     content_by_lua_file "lua/hello.lua";
//!     proxy_pass "http://127.0.0.1:9000";
//! }
//! ```

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// 单条配置指令：`name args...;` 或 `name args... { ... }`
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    /// 仅块指令非空
    pub block: Vec<Directive>,
    /// 指令所在行号（报错/日志用）
    pub line: usize,
}

impl Directive {
    pub fn arg(&self, i: usize) -> Option<&str> {
        self.args.get(i).map(|s| s.as_str())
    }

    pub fn find(&self, name: &str) -> Option<&Directive> {
        self.block.iter().find(|d| d.name == name)
    }
}

/// 顶层配置 = 一个虚拟的根 Directive
#[derive(Debug, Clone)]
pub struct Config {
    pub root: Directive,
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let tokens = lex(input)?;
        let mut parser = Parser { tokens, pos: 0 };
        let block = parser.parse_block(None)?;
        Ok(Config {
            root: Directive {
                name: "root".to_string(),
                args: vec![],
                block,
                line: 1,
            },
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    pub fn find(&self, name: &str) -> Option<&Directive> {
        self.root.find(name)
    }

    /// 所有 server 块
    pub fn servers(&self) -> impl Iterator<Item = &Directive> {
        self.root.block.iter().filter(|d| d.name == "server")
    }
}

// ---------- 词法器 ----------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// 标识符或裸词参数
    Word(String),
    /// 引号字符串参数
    Quoted(String),
    /// `{`
    OpenBrace,
    /// `}`
    CloseBrace,
    /// `;`
    Semicolon,
}

fn lex(input: &str) -> Result<Vec<(Token, usize)>, ConfigError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut line = 1usize;
    let n = chars.len();

    while i < n {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' => i += 1,
            '#' => {
                while i < n && chars[i] != '\n' {
                    i += 1;
                }
            }
            '{' => {
                tokens.push((Token::OpenBrace, line));
                i += 1;
            }
            '}' => {
                tokens.push((Token::CloseBrace, line));
                i += 1;
            }
            ';' => {
                tokens.push((Token::Semicolon, line));
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < n {
                    let ch = chars[i];
                    if ch == '\\' && i + 1 < n {
                        let next = chars[i + 1];
                        s.push(match next {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                        i += 2;
                        continue;
                    }
                    if ch == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    if ch == '\n' {
                        line += 1;
                    }
                    s.push(ch);
                    i += 1;
                }
                if !closed {
                    return Err(ConfigError::Parse {
                        line,
                        message: "unterminated string literal".into(),
                    });
                }
                tokens.push((Token::Quoted(s), line));
            }
            _ => {
                let mut s = String::new();
                while i < n {
                    let ch = chars[i];
                    if ch.is_whitespace() || "{};#".contains(ch) {
                        break;
                    }
                    s.push(ch);
                    i += 1;
                }
                tokens.push((Token::Word(s), line));
            }
        }
    }
    Ok(tokens)
}

// ---------- 解析器 ----------

struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&(Token, usize)> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<(Token, usize)> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_block(&mut self, term: Option<usize>) -> Result<Vec<Directive>, ConfigError> {
        let mut directives = Vec::new();
        loop {
            let (tok, line) = match self.peek() {
                Some(t) => t.clone(),
                None => {
                    if term.is_some() {
                        let eof_line = self.tokens.last().map(|t| t.1).unwrap_or(1);
                        return Err(ConfigError::Parse {
                            line: eof_line,
                            message: "unexpected end of file, missing '}'".into(),
                        });
                    }
                    return Ok(directives);
                }
            };
            match tok {
                Token::CloseBrace => {
                    if term.is_none() {
                        return Err(ConfigError::Parse {
                            line,
                            message: "unexpected '}'".into(),
                        });
                    }
                    self.pos += 1;
                    return Ok(directives);
                }
                Token::Semicolon => {
                    // 空指令（分号前无内容），跳过
                    self.pos += 1;
                }
                Token::Word(name) => {
                    self.pos += 1;
                    let mut args = Vec::new();
                    let block;
                    loop {
                        match self.peek() {
                            Some((Token::Word(a), _)) | Some((Token::Quoted(a), _)) => {
                                args.push(a.clone());
                                self.pos += 1;
                            }
                            Some((Token::Semicolon, _)) => {
                                self.pos += 1;
                                block = Vec::new();
                                break;
                            }
                            Some((Token::OpenBrace, _)) => {
                                self.pos += 1;
                                block = self.parse_block(Some(line))?;
                                break;
                            }
                            Some((Token::CloseBrace, l)) => {
                                return Err(ConfigError::Parse {
                                    line: *l,
                                    message: format!(
                                        "directive '{name}' not terminated by ';'"
                                    ),
                                });
                            }
                            None => {
                                return Err(ConfigError::Parse {
                                    line,
                                    message: format!(
                                        "directive '{name}' not terminated by ';'"
                                    ),
                                });
                            }
                        }
                    }
                    directives.push(Directive { name, args, block, line });
                }
                Token::OpenBrace => {
                    return Err(ConfigError::Parse {
                        line,
                        message: "unexpected '{{' at statement start".into(),
                    });
                }
                Token::Quoted(_) => {
                    return Err(ConfigError::Parse {
                        line,
                        message: "unexpected quoted string at statement start".into(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        # 注释
        worker_processes auto;

        server {
            listen 8080;
            server_name localhost;

            location /api {
                content_by_lua_file "lua/api.lua";
            }

            location /static {
                root "public";
            }
        }
    "#;

    #[test]
    fn parses_sample() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let server = cfg.servers().next().unwrap();
        assert_eq!(server.find("listen").unwrap().arg(0), Some("8080"));
        assert_eq!(server.find("server_name").unwrap().arg(0), Some("localhost"));
    }

    #[test]
    fn finds_location() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let server = cfg.servers().next().unwrap();
        let loc = server.block.iter().find(|d| d.name == "location").unwrap();
        assert_eq!(loc.arg(0), Some("/api"));
        assert!(loc.find("content_by_lua_file").is_some());
    }

    #[test]
    fn rejects_unclosed_block() {
        let err = Config::parse("server { listen 80;").unwrap_err();
        assert!(err.to_string().contains("missing '}'"));
    }
}
