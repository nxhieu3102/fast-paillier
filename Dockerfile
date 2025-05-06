FROM redis:7.0-alpine

# Expose Redis port
EXPOSE 6379

# Use custom redis.conf
COPY redis.conf /usr/local/etc/redis/redis.conf

# Run Redis with the custom config
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"] 
