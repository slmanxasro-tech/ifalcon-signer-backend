FROM ubuntu:22.04

# دابەزاندنی Node.js و کەرەستەی زەروری بۆ zsign
RUN apt-get update && apt-get install -y \
    curl git g++ clang make libssl-dev libzip-dev \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs

# دابەزاندن و دروستکردنی پرۆگرامی zsign
RUN git clone https://github.com/zhlynn/zsign.git /tmp/zsign \
    && cd /tmp/zsign && g++ *.cpp -lcrypto -O3 -o /usr/local/bin/zsign \
    && rm -rf /tmp/zsign

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p uploads public

EXPOSE 3000
CMD ["npm", "start"]
