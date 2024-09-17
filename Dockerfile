FROM openjdk:17-jdk

WORKDIR  /app

COPY target/aliboy-security-1.0.0.jar /app/aliboy-security.jar

EXPOSE 8080

CMD ["java", "-jar", "aliboy-security.jar"]