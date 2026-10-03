FROM eclipse-temurin:21.0.5_11-jre-jammy
ADD https://github.com/checkstyle/checkstyle/releases/download/checkstyle-10.21.1/checkstyle-10.21.1-all.jar /opt/checkstyle.jar
ENTRYPOINT ["java", "-jar", "/opt/checkstyle.jar"]
