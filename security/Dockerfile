FROM python

EXPOSE 8080

WORKDIR /opt

COPY requirements.txt ./
RUN pip install -r requirements.txt

ARG RUN_SCRIPT

COPY * ./

CMD ["bash","-c","python3 -u $RUN_SCRIPT"]
#docker run -p 8080:8080 --rm -it $(docker build -q .)