# Copyright 2019 Tad Lebeck
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


FROM ubuntu:18.04

# TODO Can we just install library for libunwind-dev and libaio-dev?
RUN apt-get update && apt-get install -y apt-transport-https curl libprotobuf-c1 libunwind-dev libaio-dev

WORKDIR /root
# tuned for use with jenkins jobs
COPY build/libfuse3-dev.deb .
RUN dpkg -i libfuse3-dev.deb
RUN echo "/usr/local/lib/x86_64-linux-gnu" | tee -a /etc/ld.so.conf.d/x86_64-linux-gnu.conf
RUN ldconfig
COPY build/Debug/nuvo/nuvo deploy/nuvo.sh /opt/nuvoloso/bin/
RUN chmod +x /opt/nuvoloso/bin/nuvo.sh /opt/nuvoloso/bin/nuvo

RUN mkdir -p /var/local/nuvoloso

EXPOSE 32145

# The script will provide the default arguments to the nuvo program.
# The managed cluster YAML can provide additional arguments
ENTRYPOINT ["/opt/nuvoloso/bin/nuvo.sh", "port=32145" ]
