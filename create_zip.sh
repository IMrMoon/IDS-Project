#!/bin/bash
# create_zip.sh – הפקת קובץ ZIP נקי לשיתוף
# סקריפט זה אורז את הפרויקט לקובץ ZIP תוך דילוג על קבצים ותיקיות
# שאינם נדרשים לשיתוף (סביבת venv, נתונים זמניים, קבצי מודל, יומני ריצה וכד׳).

set -e

ARCHIVE_NAME="software_safety_project_share.zip"

echo "יוצר ארכיון $ARCHIVE_NAME …"
# ניתן להריץ את הסקריפט מתוך תיקיית הפרויקט הראשית
zip -r "$ARCHIVE_NAME" . \
    -x "venv/*" \
    -x "data/*" \
    -x "logs/*" \
    -x "analysis_results/*" \
    -x "slides/*" \
    -x "**/__pycache__/*" \
    -x "*.pyc" \
    -x "*.joblib" \
    -x "*.pkl" \
    -x "*.log" \
    -x "*.zip"

echo "הארכיון נוצר בהצלחה."