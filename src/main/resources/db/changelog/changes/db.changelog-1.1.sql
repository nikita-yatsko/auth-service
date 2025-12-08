--liquibase formatted sql

--changeset nyatska:2
INSERT INTO auth_users (username, password, role)
VALUES ('admin', '$2a$10$ixyUizBVZiooVBSnwMmC4e4sa0/dI0X6S.jFs2k1hL3sAkJAsgS0K', 'ADMIN'),
       ('nikita', '$2a$10$ixyUizBVZiooVBSnwMmC4e4sa0/dI0X6S.jFs2k1hL3sAkJAsgS0K', 'USER');
