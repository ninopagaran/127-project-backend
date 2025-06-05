# Use a Python base image
FROM python:3.10-slim-buster

# Set the working directory inside the container
WORKDIR /app

# Copy requirements.txt and install Python dependencies
# This allows Docker to cache this layer if requirements.txt doesn't change
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
# This includes database.py and any other Flask application files
COPY . .

# IMPORTANT: Initialize the database during the build process.
# This creates the 'attendance.db' file and sets up its schema.
# If attendance.db already exists in a mounted volume, this step's effect might be overridden
# by the volume's contents upon container start.
RUN python database.py

# Expose the port your Flask application runs on (default is 5000)
EXPOSE 5000

# Set Flask environment variables
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_DEBUG=0

# Command to run the Flask application
# For production, it's highly recommended to use a production-ready WSGI server like Gunicorn
# CMD ["flask", "run"] # Use this only for development/simple cases

# Recommended production CMD (if you have gunicorn in requirements.txt)
# CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "your_app_module:app"]
# Replace 'your_app_module' with the name of your Flask application file (e.g., 'app' if your app is in app.py)
# and 'app' with the name of your Flask app instance (e.g., 'app = Flask(__name__)').

# Assuming a simple Flask app.py and that `flask run` is sufficient for your use case:
CMD ["flask", "run"]
