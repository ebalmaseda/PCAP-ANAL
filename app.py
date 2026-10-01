from flask import Flask, render_template, request
from analyzer import analyze_pcap
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        file = request.files.get("pcap")

        if file and file.filename:

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            file.save(filepath)

            stats = analyze_pcap(filepath)
            #print(type(stats))
            #print(stats)

            return render_template(
                "report.html",
                stats=stats
            )

    return render_template("index.html")


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )