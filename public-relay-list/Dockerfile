FROM python

EXPOSE 8080

WORKDIR /opt
COPY * .

RUN pip install -r requirements.txt

CMD ["bash","run.sh"]
# docker run -p 8080:8080 --rm -it $(docker build -q .)