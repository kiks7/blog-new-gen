#!/usr/bin/env python3
"""Build static blog HTML from markdown sources.

Layout:
    content/posts/<slug>.md         post source (YAML frontmatter + markdown body)
    content/posts/images/*          referenced from markdown as ![alt](images/foo.png)
    templates/{index,blog,post}.html  page templates with {{key}} placeholders
    static/*                        copied as-is into the output root
    _site/                          build output (deploy this)

Run:  python build.py
"""
import re
import shutil
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).parent.resolve()
CONTENT_POSTS = ROOT / "content" / "posts"
TEMPLATES = ROOT / "templates"
STATIC = ROOT / "static"
OUT = ROOT / "_site"

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)", re.DOTALL)


def parse_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("missing frontmatter block (--- ... ---)")
    meta_raw, body = m.groups()
    meta = {}
    for line in meta_raw.splitlines():
        if not line.strip() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        meta[key.strip()] = value.strip().strip('"').strip("'")
    return meta, body


def slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower())
    return re.sub(r"-+", "-", s).strip("-")


def style_headings_and_collect(html):
    """Restyle h2–h6 (anchor-wrap, prefix with `# `, level-scoped class).

    Only h2 entries are returned for the TOC.
    """
    headings = []

    def replace(match):
        level = int(match.group(1))
        inner = match.group(2)
        text = re.sub(r"<[^>]+>", "", inner).strip()
        slug = slugify(text)
        headings.append((level, text, slug))
        return (
            f'<h{level} id="{slug}" class="post-sub post-sub-{level}">'
            f'<a href="#{slug}"># {text}</a>'
            f'</h{level}>'
        )

    html = re.sub(r"<h([2-6])[^>]*>(.+?)</h\1>", replace, html, flags=re.DOTALL)
    return html, headings


def style_paragraphs(html):
    return re.sub(r"<p>", '<p class="post-p">', html)


def resize_images(html):
    """Honor Obsidian-style ![alt|W](src) and ![alt|WxH](src)."""
    img_re = re.compile(r"<img\b([^>]*)>")
    alt_re = re.compile(r'\balt="([^"]*)"')
    size_re = re.compile(r"\|(\d+)(?:x(\d+))?$")

    def repl(match):
        attrs = match.group(1)
        alt_match = alt_re.search(attrs)
        if not alt_match:
            return match.group(0)
        size_match = size_re.search(alt_match.group(1))
        if not size_match:
            return match.group(0)
        clean_alt = alt_match.group(1)[: size_match.start()]
        extra = f' width="{size_match.group(1)}"'
        if size_match.group(2):
            extra += f' height="{size_match.group(2)}"'
        new_attrs = attrs.replace(alt_match.group(0), f'alt="{clean_alt}"{extra}')
        return f"<img{new_attrs}>"

    return img_re.sub(repl, html)


def render_toc(headings):
    if not headings:
        return ""
    rendered = []
    h2_count = 0
    for level, text, slug in headings:
        if level == 2:
            h2_count += 1
            num = f'<span class="toc-num">{h2_count:02d}</span>'
        else:
            num = ""
        rendered.append(
            f'          <li class="toc-item toc-item-{level}">\n'
            f'            <a href="#{slug}">{num}{text}</a>\n'
            '          </li>'
        )
    items = "\n".join(rendered)
    return (
        '      <div class="toc">\n'
        '        <button class="toc-head" aria-expanded="false">\n'
        '          <span class="toc-caret">▸</span>\n'
        '          <span class="toc-label">table of contents</span>\n'
        f'          <span class="toc-count dim">{len(headings)}</span>\n'
        '        </button>\n'
        '        <ol class="toc-list">\n'
        f'{items}\n'
        '        </ol>\n'
        '      </div>'
    )


def fill(template, **values):
    out = template
    for key, value in values.items():
        out = out.replace("{{" + key + "}}", value)
    return out


def build():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    for path in STATIC.iterdir():
        if path.is_file():
            shutil.copy2(path, OUT / path.name)

    index_tpl = (TEMPLATES / "index.html").read_text(encoding="utf-8")
    (OUT / "index.html").write_text(index_tpl, encoding="utf-8")

    post_tpl = (TEMPLATES / "post.html").read_text(encoding="utf-8")
    posts_out = OUT / "posts"
    posts_out.mkdir(parents=True)

    posts = []
    for md_path in sorted(CONTENT_POSTS.glob("*.md")):
        text = md_path.read_text(encoding="utf-8")
        meta, body_md = parse_frontmatter(text)
        try:
            title = meta["title"]
            date = meta["date"]
        except KeyError as missing:
            sys.exit(f"{md_path}: missing frontmatter key {missing}")
        author = meta.get("author", "kiks")
        slug = md_path.stem

        md = markdown.Markdown(
            extensions=["fenced_code", "codehilite", "tables"],
            extension_configs={"codehilite": {"guess_lang": False, "css_class": "codehilite"}},
        )
        body_html = md.convert(body_md)
        body_html, headings = style_headings_and_collect(body_html)
        body_html = style_paragraphs(body_html)
        body_html = resize_images(body_html)
        toc_html = render_toc(headings)

        page = fill(
            post_tpl,
            title=title,
            year=date[:4],
            author=author,
            toc=toc_html,
            body=body_html,
        )
        (posts_out / f"{slug}.html").write_text(page, encoding="utf-8")
        posts.append({"slug": slug, "title": title, "date": date})

    img_src = CONTENT_POSTS / "images"
    if img_src.exists() and any(img_src.iterdir()):
        shutil.copytree(img_src, posts_out / "images", dirs_exist_ok=True)

    posts.sort(key=lambda p: p["date"], reverse=True)
    rows = "\n".join(
        '      <li>\n'
        f'        <a class="row" href="posts/{p["slug"]}.html">\n'
        f'          <span class="dim row-date">{p["date"][:4]}</span>\n'
        f'          <span class="row-title">{p["title"]}</span>\n'
        '        </a>\n'
        '      </li>'
        for p in posts
    )
    blog_tpl = (TEMPLATES / "blog.html").read_text(encoding="utf-8")
    (OUT / "blog.html").write_text(fill(blog_tpl, rows=rows), encoding="utf-8")

    print(f"Built {len(posts)} post(s) → {OUT.relative_to(ROOT)}/")


if __name__ == "__main__":
    build()
