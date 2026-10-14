# LearnON Branding Guide

## Logo Assets

The official LearnON logo is located at `public/logo.png`.

### Logo Specifications
- **File**: `public/logo.png`
- **Dimensions**: 667 x 655 pixels
- **Format**: PNG with alpha transparency
- **Color**: Black on transparent background

### Usage Guidelines

#### Docker Images
The logo is included in Docker images at `/app/assets/logo.png`:
```dockerfile
COPY public/logo.png /app/assets/logo.png
```

#### Documentation
Use the logo in README and documentation:
```markdown
<p align="center">
  <img src="public/logo.png" alt="LearnON logo" width="180">
</p>
```

#### Social Media & Marketing
- Minimum size: 100px width
- Preferred size: 300px width
- Always maintain aspect ratio (approximately 1:1)
- Use on white or light backgrounds for best visibility

### Color Palette

Based on the logo design:
- **Primary**: Black (#000000)
- **Background**: Transparent or White (#FFFFFF)

### Typography

For "LearnON" text accompanying the logo:
- **Font**: Modern sans-serif (Inter, Roboto, or system default)
- **Weight**: Bold or Semi-bold
- **Case**: Title case ("LearnON")

### Examples

#### GitHub Profile/Repository
```html
<div align="center">
  <img src="public/logo.png" width="200" alt="LearnON Gateway">
  <h1>LearnON</h1>
  <p>High-performance gateway server like Nginx, 100% in Rust</p>
</div>
```

#### Docker Hub
Use the logo as the repository avatar and include in description.

#### Documentation Headers
```markdown
# LearnON Gateway

<img src="../public/logo.png" align="right" width="100">
```

### File Locations

| Location | Purpose |
|----------|---------|
| `public/logo.png` | Source logo file |
| `assets/logo-custom.png` | Build artifact copy |
| Docker: `/app/assets/logo.png` | Runtime asset |
| Kubernetes ConfigMap | Embedded in deployment |

### Do's and Don'ts

✅ **DO:**
- Use the original PNG file without modification
- Maintain clear space around the logo (at least 20% of logo width)
- Use on contrasting backgrounds
- Keep the logo at readable sizes (min 100px)

❌ **DON'T:**
- Stretch or distort the logo
- Change the colors
- Add effects (shadows, glows, etc.)
- Place on busy/cluttered backgrounds
- Use pixelated or low-resolution versions

### Contact

For branding questions or high-resolution assets, contact: yxpil

---

*Last updated: 2026-10-14*
