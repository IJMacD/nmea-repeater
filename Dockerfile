FROM alpine AS build
RUN apk add --update build-base
WORKDIR /app
COPY src /app/
RUN gcc -o main main.c

FROM alpine
WORKDIR /app
COPY --from=build /app/main /app/
EXPOSE 10110/udp
EXPOSE 10110/tcp
CMD [ "/app/main" ]