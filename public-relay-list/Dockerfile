FROM python

EXPOSE 8080

WORKDIR /opt

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY * ./

CMD ["bash","run.sh"]
# docker run -p 8080:8080 --rm -it $(docker build -q .)