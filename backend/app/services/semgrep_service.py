import shutil
import stat
import zipfile
from pathlib import Path


def extract_upload(archive_path: Path, dest_dir: Path) -> Path:
    """Extract zip/tar upload and return project root."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    if archive_path.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            root = dest_dir.resolve()
            for info in zf.infolist():
                name = info.filename.replace("\\", "/")
                target = (root / name).resolve()
                if target != root and root not in target.parents:
                    raise ValueError("上传压缩包包含越界路径")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise ValueError("上传压缩包不允许包含符号链接")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
    else:
        shutil.copytree(archive_path, dest_dir, dirs_exist_ok=True)

    children = [p for p in dest_dir.iterdir() if p.name not in ("__MACOSX", ".DS_Store")]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir
