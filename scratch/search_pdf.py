import glob
import pypdf

targets = ["6645", "5569", "audit_record_6645", "audit_record_5569"]
for p in glob.glob("dataset/evidence/**/*.pdf", recursive=True):
    try:
        reader = pypdf.PdfReader(p)
        txt = ""
        for page in reader.pages:
            txt += page.extract_text() or ""
        for t in targets:
            if t in txt:
                print(f"Found {t} in {p}")
    except Exception as e:
        print(f"Error {p}: {e}")
