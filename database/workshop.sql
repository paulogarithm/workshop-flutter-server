drop table if exists users;
drop table if exists posts;
drop table if exists comments;

create table if NOT exists users (
    id serial primary key,
    nickname text not null,
    password text not null
);

create table if not exists posts (
    id serial primary key,
    owner int not null,
    title text not null,
    content text not null
);

create table if not exists comments (
    id serial primary key,
    post int not null,
    owner int not null,
    content text not null
);