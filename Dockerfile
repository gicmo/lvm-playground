FROM fedora:latest

RUN dnf --enablerepo=updates-testing -y update && \
    dnf --enablerepo=updates-testing -y install lvm2

RUN mkdir /code
ADD create-lvm.sh /code
ADD container.py /code
ENTRYPOINT [ "/code/container.py" ]