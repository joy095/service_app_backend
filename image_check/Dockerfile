FROM python:3.12-alpine

WORKDIR /app

# Install dependencies
COPY ./requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the FastAPI app
COPY ./app .

# Expose the FastAPI port
EXPOSE 8083

# Run the FastAPI app using uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8083"]