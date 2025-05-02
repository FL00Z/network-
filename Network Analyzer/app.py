import threading
import time
from flask import Flask, render_template
from Analyzer_cleaned import Analyzer

app = Flask(__name__)
analyzer = Analyzer()
scan_results = []  # Shared list to hold discovered devices

def run_scan():
    global scan_results
    analyzer.PrivateScanner.ARP_DiscoverHosts(
        maxHostgroup=5, verbose=False, mapping=False, save_to_file=False
    )
    scan_results = analyzer.PrivateScanner.DiscoveredData

@app.route("/")
def home():
    global scan_results
    if not scan_results:
        # Start the background scan if it hasn't been run yet
        thread = threading.Thread(target=run_scan)
        thread.start()
        return """
        <h2>Scanning the network...</h2>
        <p>Please <a href="/">refresh the page</a> in a few seconds.</p>
        """
    else:
        return render_template("index.html", devices=scan_results)

if __name__ == "__main__":
    app.run(debug=True)
