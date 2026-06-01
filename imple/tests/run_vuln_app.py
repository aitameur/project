"""Lance l'app Flask volontairement vulnérable sur 127.0.0.1:5001
(utile pour tester manuellement le CLI : `python main.py --url http://127.0.0.1:5001`)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest import create_vulnerable_app

if __name__ == "__main__":
    app = create_vulnerable_app()
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)
