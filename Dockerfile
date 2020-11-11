FROM ubuntu:16.04

RUN apt update
RUN apt install -y libsdl1.2-dev libtool-bin libglib2.0-dev libz-dev libpixman-1-dev libncurses5-dev libncursesw5-dev

RUN apt install -y gcc-multilib vim gdb

CMD ["/bin/bash"]