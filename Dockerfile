ARG PHP_VER

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
        librabbitmq-dev; \
    rm -rf /var/lib/apt/lists/*; \
    cd /usr/src; \
    dir=/usr/src/jpegsrc; \
    curl -fsSL -o jpegsrc.tar.gz http://www.ijg.org/files/jpegsrc.v9c.tar.gz; \
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
    docker-php-ext-enable amqp redis mcrypt; \
    pecl install xdebug; \
    rm -rf /tmp/pear;

COPY entrypoint /usr/local/bin/

RUN set -eux; \
    apt-get update && apt-get install -y \
        cron; \
    chmod +x /usr/local/bin/entrypoint; \
    rm -rf /var/lib/apt/lists/*;

# 修改fpm运行用户
RUN set -eux; \
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
