FROM nginx:alpine

# Copy nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy web files
COPY html/ /var/www/html/

# Create log directory
RUN mkdir -p /var/log/honeypot && \
    chown -R nginx:nginx /var/log/honeypot && \
    chown -R nginx:nginx /var/www/html

EXPOSE 80

CMD nginx -g 'daemon off;'
