FROM alpine:latest
RUN apk add --update --no-cache bind-tools tcpdump openrc iptables ip6tables ipset iputils iproute2 drill
RUN rc-update add iptables
RUN rc-update add ip6tables
RUN rc-update add ipset