ARG PHP_VER=7.3.25-fpm

FROM php:${PHP_VER}

RUN sed -i 's#http://deb.debian.org#https://mirrors.aliyun.com#g' /etc/apt/sources.list

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN set -eux; \
    apt-get update && apt-get install -y \
        libfreetype6-dev \
        libpng-dev \
        libzip-dev \
        libmcrypt-dev \
        librabbitmq-dev \
        libgrpc-dev \
        protobuf-compiler-grpc \
        libcurl4-openssl-dev \
        libgrpc++-dev \
        cron; \
    rm -rf /var/lib/apt/lists/*; \
    cd /usr/src; \
    dir=/usr/src/jpegsrc; \
    curl -fsSL -o jpegsrc.tar.gz http://www.ijg.org/files/jpegsrc.v9d.tar.gz; \
    mkdir -p "$dir"; \
    tar -zxf jpegsrc.tar.gz -C "$dir" --strip-components=1; \
    rm jpegsrc.tar.gz; \
    cd "$dir"; \
    CFLAGS="-O3 -fPIC" ./configure; \
    make && make install; \
    rm -rf "$dir"; \
    docker-php-ext-configure gd --with-jpeg-dir= --with-freetype-dir=; \
    docker-php-ext-install -j$(nproc) gd bcmath pdo_mysql zip; \
    pecl install amqp; \
    pecl install redis; \
    pecl install mcrypt; \
    pecl install xdebug; \
    dir=/usr/src/skywalking; \
    curl -fsSL -o skywalking.tar.gz https://github.com/SkyAPM/SkyAPM-php-sdk/archive/master.tar.gz; \
    mkdir -p "$dir"; \
    tar -zxf skywalking.tar.gz -C "$dir" --strip-components=1; \
    rm skywalking.tar.gz; \
    cd "$dir"; \
    phpize && ./configure && make && make install; \
    rm -rf "$dir"; \
    docker-php-ext-enable amqp redis mcrypt skywalking; \
    rm -rf /tmp/pear;

COPY entrypoint /usr/local/bin/

RUN set -eux; \
    chmod +x /usr/local/bin/entrypoint; \
    groupadd -g 1000 www; \
    useradd -g 1000 -u 1000 -b /var -s /bin/bash www; \
    cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; \
    { \
        echo '[www]'; \
        echo 'user = www'; \
        echo 'group = www'; \
    } | tee /usr/local/etc/php-fpm.d/zz-www.conf; \
    { \
            echo 'KWM_SYSTEM_ENVIRON = prod'; \
            echo 'KWM_SYSTEM_CONFIG_PATH = /data/phpConfig'; \
            echo 'KWM_SYSTEM_RUNTIME_PATH = /data/phpRuntime'; \
            echo 'date.timezone = Asia/Shanghai'; \
            echo 'upload_max_filesize = 100M'; \
            echo 'zend_extension=opcache'; \
            echo 'opcache.enable=1'; \
            echo 'opcache.validate_timestamps=0'; \
    } | tee /usr/local/etc/php/conf.d/docker-php.ini;

ENTRYPOINT ["entrypoint"]
