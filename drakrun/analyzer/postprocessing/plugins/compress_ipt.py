import zipfile

from drakrun.lib.paths import IPT_DIR, IPT_ZIP

from .plugin_base import PostprocessContext


def compress_ipt(context: PostprocessContext) -> None:
    """
    Compress the directory specified by dirpath to target_zip file.
    """
    analysis_dir = context.analysis_dir
    # Compress IPT traces, they're quite large however they compress well
    ipt_path = analysis_dir / IPT_DIR
    ipt_zip_path = analysis_dir / IPT_ZIP

    zipf = zipfile.ZipFile(ipt_zip_path, "w", zipfile.ZIP_DEFLATED)

    for ipt_file in ipt_path.rglob("*"):
        zip_path = ipt_file.relative_to(analysis_dir).as_posix()
        zipf.write(ipt_file, zip_path)
        ipt_file.unlink()
