from flask import Flask, render_template, request, send_file, redirect, url_for, session
from PIL import Image
from pypdf import PdfWriter, PdfReader
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import pymupdf
import os
import zipfile
import uuid
import traceback

from database import get_connection


# =========================
# ENVIRONMENT VARIABLES
# =========================

load_dotenv()


# =========================
# FLASK APP
# =========================

app = Flask(__name__)


# =========================
# SECURITY HEADERS
# =========================

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response


app.secret_key = os.getenv("SECRET_KEY")


# =========================
# SESSION SECURITY
# =========================

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# =========================
# CSRF PROTECTION
# =========================

csrf = CSRFProtect(app)


# =========================
# RATE LIMITER
# =========================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)


# =========================
# MAXIMUM UPLOAD SIZE
# =========================

app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024


# =========================
# FOLDERS
# =========================

UPLOAD_FOLDER = "uploads"
COMPRESSED_FOLDER = "compressed"
RESIZED_FOLDER = "resized"
MERGED_FOLDER = "merged"
SPLIT_FOLDER = "split"
PDF_TO_JPG_FOLDER = "pdf_to_jpg"


for folder in [
    UPLOAD_FOLDER,
    COMPRESSED_FOLDER,
    RESIZED_FOLDER,
    MERGED_FOLDER,
    SPLIT_FOLDER,
    PDF_TO_JPG_FOLDER
]:
    os.makedirs(folder, exist_ok=True)


# =========================
# UPLOAD SECURITY
# =========================

ALLOWED_IMAGE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "webp"
}

ALLOWED_PDF_EXTENSIONS = {
    "pdf"
}


def get_file_extension(filename):

    if not filename or "." not in filename:
        return ""

    return filename.rsplit(".", 1)[1].lower()


def is_allowed_image(filename):

    extension = get_file_extension(filename)

    return extension in ALLOWED_IMAGE_EXTENSIONS


def is_allowed_pdf(filename):

    extension = get_file_extension(filename)

    return extension in ALLOWED_PDF_EXTENSIONS


def safe_filename(filename):

    filename = secure_filename(filename)

    if not filename:
        return None

    return filename


def validate_image(file):

    try:

        file.stream.seek(0)

        image = Image.open(file.stream)

        image.verify()

        file.stream.seek(0)

        return True

    except Exception:

        try:
            file.stream.seek(0)
        except Exception:
            pass

        return False


def validate_pdf(file):

    temp_path = None

    try:

        temporary_name = (
            f"validate_{uuid.uuid4().hex}.pdf"
        )

        temp_path = os.path.join(
            UPLOAD_FOLDER,
            temporary_name
        )

        file.save(temp_path)

        reader = PdfReader(temp_path)

        if len(reader.pages) < 1:
            return False

        return True

    except Exception:

        return False

    finally:

        try:
            file.stream.seek(0)
        except Exception:
            pass

        if temp_path and os.path.exists(temp_path):

            try:
                os.remove(temp_path)
            except OSError:
                pass


# =========================
# CURRENT USER
# =========================

def get_current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    connection = get_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    return user


# =========================
# SAVE FILE RECORD
# =========================

def save_file_record(
    filename,
    tool_name,
    file_path
):

    user = get_current_user()

    if not user:
        return

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO files
        (user_id, filename, tool_name, file_path)
        VALUES (?, ?, ?, ?)
        """,
        (
            user["id"],
            filename,
            tool_name,
            file_path
        )
    )

    connection.commit()

    connection.close()


# =========================
# HOME
# =========================

@app.route("/")
def home():

    user = get_current_user()

    return render_template(
        "index.html",
        user=user
    )


# =========================
# SIGNUP
# =========================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not name or not email or not password:

            return render_template(
                "signup.html",
                error="Please fill all fields."
            )

        if len(password) < 6:

            return render_template(
                "signup.html",
                error="Password must be at least 6 characters."
            )

        connection = get_connection()

        existing_user = connection.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if existing_user:

            connection.close()

            return render_template(
                "signup.html",
                error="Email already registered."
            )

        hashed_password = generate_password_hash(
            password
        )

        cursor = connection.execute(
            """
            INSERT INTO users
            (name, email, password)
            VALUES (?, ?, ?)
            RETURNING id
            """,
            (
                name,
                email,
                hashed_password
            )
        )

        user_row = cursor.fetchone()

        connection.commit()

        user_id = user_row["id"]

        connection.close()

        session["user_id"] = user_id

        return redirect(
            url_for("home")
        )

    return render_template(
        "signup.html"
    )


# =========================
# LOGIN
# =========================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
@limiter.limit(
    "5 per minute",
    methods=["POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # LOGIN DEBUG
        print("")
        print("================================")
        print("LOGIN DEBUG")
        print("================================")
        print("LOGIN EMAIL:", repr(email))
        print("PASSWORD ENTERED:", repr(password))

        connection = get_connection()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        print(
            "USER FOUND:",
            user is not None
        )

        if user:

            try:

                password_match = check_password_hash(
                    user["password"],
                    password
                )

            except Exception as error:

                print(
                    "PASSWORD CHECK ERROR:",
                    repr(error)
                )

                password_match = False

        else:

            password_match = False

        print(
            "PASSWORD MATCH:",
            password_match
        )

        connection.close()

        if not user:

            print(
                "LOGIN RESULT: USER NOT FOUND"
            )

            return render_template(
                "login.html",
                error="Invalid email or password."
            )

        if not password_match:

            print(
                "LOGIN RESULT: WRONG PASSWORD"
            )

            return render_template(
                "login.html",
                error="Invalid email or password."
            )

        session["user_id"] = user["id"]

        print(
            "LOGIN RESULT: SUCCESS"
        )

        print(
            "USER ID:",
            user["id"]
        )

        print("================================")
        print("")

        return redirect(
            url_for("home")
        )

    return render_template(
        "login.html"
    )


# =========================
# LOGOUT
# =========================

@app.route(
    "/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# =========================
# PROFILE
# =========================

@app.route("/profile")
def profile():

    user = get_current_user()

    if not user:

        return redirect(
            url_for("login")
        )

    return render_template(
        "profile.html",
        user=user
    )


# =========================
# MY FILES
# =========================

@app.route("/my-files")
def my_files():

    user = get_current_user()

    if not user:

        return redirect(
            url_for("login")
        )

    connection = get_connection()

    files = connection.execute(
        """
        SELECT *
        FROM files
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user["id"],)
    ).fetchall()

    connection.close()

    return render_template(
        "my_files.html",
        user=user,
        files=files
    )


# =========================
# DOWNLOAD FILE
# =========================

@app.route(
    "/download/<int:file_id>"
)
def download_file(file_id):

    user = get_current_user()

    if not user:

        return redirect(
            url_for("login")
        )

    connection = get_connection()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            user["id"]
        )
    ).fetchone()

    connection.close()

    if not file_record:

        return "File not found.", 404

    file_path = file_record["file_path"]

    if not os.path.exists(file_path):

        return "File no longer exists.", 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_record["filename"]
    )


# =========================
# DELETE FILE
# =========================

@app.route(
    "/delete-file/<int:file_id>",
    methods=["POST"]
)
def delete_file(file_id):

    user = get_current_user()

    if not user:

        return redirect(
            url_for("login")
        )

    connection = get_connection()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            user["id"]
        )
    ).fetchone()

    if not file_record:

        connection.close()

        return "File not found.", 404

    file_path = file_record["file_path"]

    if os.path.exists(file_path):

        try:
            os.remove(file_path)
        except OSError:
            pass

    connection.execute(
        """
        DELETE FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            user["id"]
        )
    )

    connection.commit()

    connection.close()

    return redirect(
        url_for("my_files")
    )


# =========================
# JPG TO PDF PAGE
# =========================

@app.route("/jpg-to-pdf")
def jpg_to_pdf_page():

    user = get_current_user()

    return render_template(
        "jpg_to_pdf.html",
        user=user
    )


# =========================
# JPG TO PDF
# =========================

@app.route(
    "/jpg-to-pdf",
    methods=["POST"]
)
def jpg_to_pdf():

    files = request.files.getlist(
        "files"
    )

    valid_files = [
        file
        for file in files
        if file and file.filename != ""
    ]

    if not valid_files:

        return (
            "Please select image files.",
            400
        )

    images = []

    try:

        for file in valid_files:

            original_filename = safe_filename(
                file.filename
            )

            if not original_filename:

                return "Invalid filename.", 400

            if not is_allowed_image(
                original_filename
            ):

                return (
                    "Only JPG, JPEG, PNG and WEBP images are allowed.",
                    400
                )

            if not validate_image(file):

                return (
                    f"Invalid image file: {original_filename}",
                    400
                )

            file.stream.seek(0)

            image = Image.open(
                file.stream
            )

            if image.mode in (
                "RGBA",
                "P"
            ):

                image = image.convert(
                    "RGB"
                )

            elif image.mode != "RGB":

                image = image.convert(
                    "RGB"
                )

            images.append(image)

        if not images:

            return (
                "No valid images selected.",
                400
            )

        filename = (
            f"images_to_pdf_{uuid.uuid4().hex}.pdf"
        )

        output_path = os.path.join(
            UPLOAD_FOLDER,
            filename
        )

        first_image = images[0]

        remaining_images = images[1:]

        first_image.save(
            output_path,
            "PDF",
            resolution=100.0,
            save_all=True,
            append_images=remaining_images
        )

        save_file_record(
            filename,
            "JPG to PDF",
            output_path
        )

        return send_file(
            output_path,
            as_attachment=True,
            download_name="images_to_pdf.pdf"
        )

    except Exception:

        return (
            "Unable to convert images to PDF.",
            500
        )

    finally:

        for image in images:

            try:
                image.close()
            except Exception:
                pass


# =========================
# COMPRESS PAGE
# =========================

@app.route("/compress")
def compress_page():

    user = get_current_user()

    return render_template(
        "compress.html",
        user=user
    )


# =========================
# COMPRESS IMAGE
# =========================

@app.route(
    "/compress",
    methods=["POST"]
)
def compress_image():

    file = request.files.get(
        "file"
    )

    if not file or file.filename == "":

        return (
            "Please select an image.",
            400
        )

    original_filename = safe_filename(
        file.filename
    )

    if not original_filename:

        return "Invalid filename.", 400

    if not is_allowed_image(
        original_filename
    ):

        return (
            "Only JPG, JPEG, PNG and WEBP images are allowed.",
            400
        )

    if not validate_image(file):

        return (
            "Invalid image file.",
            400
        )

    try:

        file.stream.seek(0)

        image = Image.open(
            file.stream
        )

        if image.mode in (
            "RGBA",
            "P"
        ):

            image = image.convert(
                "RGB"
            )

        elif image.mode != "RGB":

            image = image.convert(
                "RGB"
            )

        filename = (
            f"compressed_{uuid.uuid4().hex}.jpg"
        )

        output_path = os.path.join(
            COMPRESSED_FOLDER,
            filename
        )

        image.save(
            output_path,
            "JPEG",
            quality=50,
            optimize=True
        )

        image.close()

        save_file_record(
            filename,
            "Compress Image",
            output_path
        )

        return send_file(
            output_path,
            as_attachment=True,
            download_name="compressed_image.jpg"
        )

    except Exception:

        return (
            "Unable to compress image.",
            500
        )


# =========================
# RESIZE PAGE
# =========================

@app.route("/resize")
def resize_page():

    user = get_current_user()

    return render_template(
        "resize.html",
        user=user
    )


# =========================
# RESIZE IMAGE
# =========================

@app.route(
    "/resize",
    methods=["POST"]
)
def resize_image():

    file = request.files.get(
        "file"
    )

    width = request.form.get(
        "width",
        ""
    ).strip()

    height = request.form.get(
        "height",
        ""
    ).strip()

    if not file or file.filename == "":

        return (
            "Please select an image.",
            400
        )

    original_filename = safe_filename(
        file.filename
    )

    if not original_filename:

        return "Invalid filename.", 400

    if not is_allowed_image(
        original_filename
    ):

        return (
            "Only JPG, JPEG, PNG and WEBP images are allowed.",
            400
        )

    if not validate_image(file):

        return (
            "Invalid image file.",
            400
        )

    try:

        width = int(width)
        height = int(height)

    except ValueError:

        return (
            "Width and height must be numbers.",
            400
        )

    if width <= 0 or height <= 0:

        return (
            "Width and height must be greater than 0.",
            400
        )

    if width > 10000 or height > 10000:

        return (
            "Maximum image dimension is 10000 x 10000.",
            400
        )

    try:

        file.stream.seek(0)

        image = Image.open(
            file.stream
        )

        if image.mode in (
            "RGBA",
            "P"
        ):

            image = image.convert(
                "RGB"
            )

        elif image.mode != "RGB":

            image = image.convert(
                "RGB"
            )

        resized_image = image.resize(
            (
                width,
                height
            )
        )

        filename = (
            f"resized_{uuid.uuid4().hex}.jpg"
        )

        output_path = os.path.join(
            RESIZED_FOLDER,
            filename
        )

        resized_image.save(
            output_path,
            "JPEG",
            quality=90
        )

        image.close()
        resized_image.close()

        save_file_record(
            filename,
            "Resize Image",
            output_path
        )

        return send_file(
            output_path,
            as_attachment=True,
            download_name="resized_image.jpg"
        )

    except Exception:

        return (
            "Unable to resize image.",
            500
        )


# =========================
# MERGE PDF PAGE
# =========================

@app.route("/merge-pdf")
def merge_pdf_page():

    user = get_current_user()

    return render_template(
        "merge_pdf.html",
        user=user
    )


# =========================
# MERGE PDF
# =========================

@app.route(
    "/merge-pdf",
    methods=["POST"]
)
def merge_pdf():

    files = request.files.getlist(
        "files"
    )

    valid_files = [
        file
        for file in files
        if file and file.filename != ""
    ]

    if len(valid_files) < 2:

        return (
            "Please select at least 2 PDF files.",
            400
        )

    temp_files = []

    try:

        writer = PdfWriter()

        for file in valid_files:

            original_filename = safe_filename(
                file.filename
            )

            if not original_filename:

                return (
                    "Invalid filename.",
                    400
                )

            if not is_allowed_pdf(
                original_filename
            ):

                return (
                    "Only PDF files are allowed.",
                    400
                )

            if not validate_pdf(file):

                return (
                    f"Invalid PDF file: {original_filename}",
                    400
                )

            file.stream.seek(0)

            temp_filename = (
                f"temp_{uuid.uuid4().hex}.pdf"
            )

            temp_path = os.path.join(
                MERGED_FOLDER,
                temp_filename
            )

            file.save(
                temp_path
            )

            temp_files.append(
                temp_path
            )

            reader = PdfReader(
                temp_path
            )

            for page in reader.pages:

                writer.add_page(
                    page
                )

        filename = (
            f"merged_{uuid.uuid4().hex}.pdf"
        )

        output_path = os.path.join(
            MERGED_FOLDER,
            filename
        )

        with open(
            output_path,
            "wb"
        ) as output_file:

            writer.write(
                output_file
            )

        save_file_record(
            filename,
            "Merge PDF",
            output_path
        )

        return send_file(
            output_path,
            as_attachment=True,
            download_name="merged.pdf"
        )

    except Exception:

        return (
            "Unable to merge PDF files.",
            500
        )

    finally:

        for temp_path in temp_files:

            if os.path.exists(
                temp_path
            ):

                try:
                    os.remove(temp_path)
                except OSError:
                    pass


# =========================
# SPLIT PDF PAGE
# =========================

@app.route("/split-pdf")
def split_pdf_page():

    user = get_current_user()

    return render_template(
        "split_pdf.html",
        user=user
    )


# =========================
# SPLIT PDF
# =========================

@app.route(
    "/split-pdf",
    methods=["POST"]
)
def split_pdf():

    file = request.files.get(
        "file"
    )

    start_page = request.form.get(
        "start_page",
        ""
    ).strip()

    end_page = request.form.get(
        "end_page",
        ""
    ).strip()

    if not file or file.filename == "":

        return (
            "Please select a PDF file.",
            400
        )

    original_filename = safe_filename(
        file.filename
    )

    if not original_filename:

        return (
            "Invalid filename.",
            400
        )

    if not is_allowed_pdf(
        original_filename
    ):

        return (
            "Only PDF files are allowed.",
            400
        )

    if not validate_pdf(file):

        return (
            "Invalid PDF file.",
            400
        )

    try:

        start_page = int(start_page)
        end_page = int(end_page)

    except ValueError:

        return (
            "Page numbers must be numbers.",
            400
        )

    if (
        start_page < 1
        or end_page < start_page
    ):

        return (
            "Invalid page range.",
            400
        )

    temp_filename = (
        f"temp_{uuid.uuid4().hex}.pdf"
    )

    temp_path = os.path.join(
        SPLIT_FOLDER,
        temp_filename
    )

    try:

        file.stream.seek(0)

        file.save(
            temp_path
        )

        reader = PdfReader(
            temp_path
        )

        total_pages = len(
            reader.pages
        )

        if (
            start_page > total_pages
            or end_page > total_pages
        ):

            return (
                f"PDF has only {total_pages} pages.",
                400
            )

        writer = PdfWriter()

        for page_number in range(
            start_page - 1,
            end_page
        ):

            writer.add_page(
                reader.pages[page_number]
            )

        filename = (
            f"split_{uuid.uuid4().hex}.pdf"
        )

        output_path = os.path.join(
            SPLIT_FOLDER,
            filename
        )

        with open(
            output_path,
            "wb"
        ) as output_file:

            writer.write(
                output_file
            )

        save_file_record(
            filename,
            "Split PDF",
            output_path
        )

        return send_file(
            output_path,
            as_attachment=True,
            download_name="split.pdf"
        )

    except Exception:

        return (
            "Unable to split PDF.",
            500
        )

    finally:

        if os.path.exists(
            temp_path
        ):

            try:
                os.remove(temp_path)
            except OSError:
                pass


# =========================
# PDF TO JPG PAGE
# =========================

@app.route("/pdf-to-jpg")
def pdf_to_jpg_page():

    user = get_current_user()

    return render_template(
        "pdf_to_jpg.html",
        user=user
    )


# =========================
# PDF TO JPG
# =========================

@app.route(
    "/pdf-to-jpg",
    methods=["POST"]
)
def pdf_to_jpg():

    file = request.files.get(
        "file"
    )

    if not file or file.filename == "":

        return (
            "Please select a PDF file.",
            400
        )

    original_filename = safe_filename(
        file.filename
    )

    if not original_filename:

        return (
            "Invalid filename.",
            400
        )

    if not is_allowed_pdf(
        original_filename
    ):

        return (
            "Only PDF files are allowed.",
            400
        )

    if not validate_pdf(file):

        return (
            "Invalid PDF file.",
            400
        )

    temp_filename = (
        f"temp_{uuid.uuid4().hex}.pdf"
    )

    temp_path = os.path.join(
        PDF_TO_JPG_FOLDER,
        temp_filename
    )

    image_files = []

    document = None

    try:

        file.stream.seek(0)

        file.save(
            temp_path
        )

        document = pymupdf.open(
            temp_path
        )

        if len(document) == 0:

            return (
                "PDF contains no pages.",
                400
            )

        for page_number in range(
            len(document)
        ):

            page = document.load_page(
                page_number
            )

            pixmap = page.get_pixmap()

            image_filename = (
                f"page_{page_number + 1}_"
                f"{uuid.uuid4().hex}.jpg"
            )

            image_path = os.path.join(
                PDF_TO_JPG_FOLDER,
                image_filename
            )

            pixmap.save(
                image_path
            )

            image_files.append(
                image_path
            )

        zip_filename = (
            f"pdf_to_jpg_{uuid.uuid4().hex}.zip"
        )

        zip_path = os.path.join(
            PDF_TO_JPG_FOLDER,
            zip_filename
        )

        with zipfile.ZipFile(
            zip_path,
            "w",
            zipfile.ZIP_DEFLATED
        ) as zip_file:

            for image_path in image_files:

                zip_file.write(
                    image_path,
                    os.path.basename(image_path)
                )

        save_file_record(
            zip_filename,
            "PDF to JPG",
            zip_path
        )

        return send_file(
            zip_path,
            as_attachment=True,
            download_name="pdf_to_jpg.zip"
        )

    except Exception:

        return (
            "Unable to convert PDF to JPG.",
            500
        )

    finally:

        if document is not None:

            try:
                document.close()
            except Exception:
                pass

        if os.path.exists(temp_path):

            try:
                os.remove(temp_path)
            except OSError:
                pass

        for image_path in image_files:

            if os.path.exists(image_path):

                try:
                    os.remove(image_path)
                except OSError:
                    pass


# =========================
# FAVICON
# =========================

@app.route("/favicon.ico")
def favicon():

    return "", 204


# =========================
# FILE TOO LARGE
# =========================

@app.errorhandler(413)
def too_large(error):

    return render_template(
        "error.html",
        message=(
            "File is too large. "
            "Maximum file size is 20 MB."
        )
    ), 413


```python
# =========================
# GENERAL ERROR
# =========================

@app.errorhandler(Exception)
def handle_error(error):

    if isinstance(error, HTTPException):
        return error

    print("")
    print("========================================")
    print("APPLICATION ERROR")
    print("========================================")
    print("ERROR TYPE:", type(error).__name__)
    print("ERROR:", repr(error))
    print("TRACEBACK:")
    traceback.print_exc()
    print("========================================")
    print("")

    return render_template(
        "error.html",
        message=(
            "Something went wrong. "
            "Please try again."
        )
    ), 500
```



# =========================
# RUN APP
# =========================

if __name__ == "__main__":

    app.run(
        debug=False
    )
