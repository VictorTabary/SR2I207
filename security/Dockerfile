FROM python

EXPOSE 8080

WORKDIR /opt

COPY requirements.txt ./
RUN pip install -r requirements.txt

ARG PORT
ARG PUBLIC_RELAY_LIST

COPY * ./

CMD ["python3","-u","run.py"]
#docker run -p 8080:8080 --rm -it $(docker build -q .)