# Use the official OpenResty base image (alpine variant)
FROM openresty/openresty:alpine-fat

# Install curl (optional, for health checks if needed)
RUN apk add --no-cache curl

# Copy custom nginx configuration
COPY ./openresty/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Expose the listening port
EXPOSE 8080

# Start OpenResty in the foreground
CMD ["openresty", "-g", "daemon off;"]
