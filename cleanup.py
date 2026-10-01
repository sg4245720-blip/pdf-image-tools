import os
import time

from database import get_connection


FOLDERS = [
    "uploads",
    "compressed",
    "resized",
    "merged",
    "split",
    "pdf_to_jpg"
]

# Files older than 24 hours will be removed
MAX_FILE_AGE_HOURS = 24


def cleanup_old_files():
    current_time = time.time()
    max_age_seconds = MAX_FILE_AGE_HOURS * 60 * 60

    deleted_files = 0
    deleted_records = 0

    connection = get_connection()

    # --------------------------------------------------
    # 1. Delete old physical files
    # --------------------------------------------------

    for folder in FOLDERS:

        if not os.path.exists(folder):
            continue

        for filename in os.listdir(folder):

            file_path = os.path.join(
                folder,
                filename
            )

            if not os.path.isfile(file_path):
                continue

            try:
                file_age = (
                    current_time
                    - os.path.getmtime(file_path)
                )

                if file_age > max_age_seconds:

                    os.remove(file_path)

                    deleted_files += 1

                    print(
                        f"Deleted old file: {file_path}"
                    )

            except OSError as error:

                print(
                    f"Could not delete {file_path}: {error}"
                )

    # --------------------------------------------------
    # 2. Remove database records for missing files
    # --------------------------------------------------

    rows = connection.execute(
        """
        SELECT id, file_path
        FROM files
        """
    ).fetchall()

    for row in rows:

        file_id = row["id"]
        file_path = row["file_path"]

        if not os.path.exists(file_path):

            connection.execute(
                """
                DELETE FROM files
                WHERE id = ?
                """,
                (file_id,)
            )

            deleted_records += 1

            print(
                f"Removed database record: {file_id}"
            )

    connection.commit()
    connection.close()

    print(
        f"Cleanup completed."
    )

    print(
        f"Files deleted: {deleted_files}"
    )

    print(
        f"Database records removed: {deleted_records}"
    )


if __name__ == "__main__":
    cleanup_old_files()