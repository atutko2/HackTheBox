# Databases

## Intro to Databases

This section just covers the various types of databases that exist and historically what created them. The general overview is that we created ways to store data efficiently and one of these ways was SQL.

## Types of Databases

This covers the types of databases.

Relational databases are the most common and MySQL is the most common example of one.

In a relational database data is stored in a table with a key. This key gives you quick access to all we know about a specific entity in the table. For example in a customer table, the key would give us all we know about a specific customer.

In MySQL and other relational DBMS there are also ways to link other tables to each other. For instance a customer table might have an id as their key and another table might have a column called user_id to link the two together. This provides an easy way to get information from that table related to the customer we are looking at.

Non-relational databases (also called NoSQL) do not use tables, rows, and columns, or keys to store the data. Instead it stores the data using various models. Since there is no defined structure of data, storage is flexible. 

There are four common storage models:
Key-Value
Document-Based
Wide-Column
Graph

In Key-Value, data is usually stored in JSON or XML format. And it generates an ID for each key, where the value is the data

Data storage like this is most often compared to a dictionary in modern languages like Python. The most common form of NoSQL DB is MongoDB.

# MySQL

## Intro to MySQL

This section is an introduction of how to use MySQL. It gives tips on how to connect to a database, create a database, create tables, etc.

Some useful commands they provided:
`mysql -u root -p` (Connects as root and asks for password)
`mysql -u root -h docker.hackthebox.eu -P 3306 -p` Connects to a specific server as root
`CREATE DATABASE users;` (Creates a database names users)
`SHOW DATABASES;` (Shows all existing databases)
`USE users;` (Switches to acesssing the users database)

For creating tables we need to define which datatype will be stored in each column. So for instance a column called username would likely be a string of some type. These are usually stored as a varchar in the database. An example of a create table call looks like:

`CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );`

We can then run `SHOW TABLES;` to show all the tables on the current database and we will see that logins exists.

Then if we want to see how logins is structured, we can do `DESCRIBE logins;`

There are other things we can do when creating tables to make it better for data structuring. For instance we can add the NOT NULL flag to make sure a specific cell is never NULL. On Ints we can add the AUTO_INCREMENT flag to make it increase from the last one automatically. If the cell needs to be unique we can add the UNIQUE flag. On dates we can the DEFAULT NOW() flag. And finally we can define what we want our primary key to be by using PRIMARY KEY (<column name>)

An example using the logins table:
`CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );`

The test on this section is:
Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database? 

Once we start the instance we can connect using:
`mysql -u root -h <IP> -P <PORT> -p`
Then simply run `SHOW DATABASES;`

The answer was employees.

## SQL Statements

This section covers relavent and important SQL statements.

The examples include how to insert into a table. We can insert into a table like:
`INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');`

But we don't actually have to define the id column or date because these have default values. So we can do:
`INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');`

Then to retrieve stuff from a table we can use a select statement. If we do `SELECT * FROM table_name;` it will get everything in a table.

Or we can do `SELECT column1, column2 FROM table_name;` and just get the first two columns.

We can use DROP to remove tables from a database. An example of this would be `DROP TABLE logins;`

If we want to add a new column to a table, we can use ALTER. An example of this:
`ALTER TABLE logins ADD newColumn INT;`

Or we can change an existing column:
`ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;`

We can change a columns datatype with MODIFY:
`ALTER TABLE logins MODIFY oldColumn DATE;`

And we can also a DROP a column:
`ALTER TABLE logins DROP oldColumn;`

We can use UPDATE to change specific records in a table:
`UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;`

An example of this could look like:
`UPDATE logins SET password = 'change_password' WHERE id > 1;`

The question in this section was:
What is the department number for the 'Development' department? 

To get this we first need to run `use employees;` to switch to that database.
Then we can run `SHOW TABLES;` to see that there is a departments table.
Then we can run `SELECT * FROM departments;` to get the answer

## Query Results

This section just covers how to filter and order our results.

If we want to sort our results we can using ORDER BY, this defaults to ascending but can use DESC to flip this.
Examples:
`SELECT * FROM logins ORDER BY password;`
`SELECT * FROM logins ORDER BY password DESC;`

You can also sort by multiple columns like:
`SELECT * FROM logins ORDER BY password DESC, id ASC;`

If we want to limit how many results are returned we can use LIMIT like:
`SELECT * FROM logins LIMIT 2;`

If we wanted to LIMIT results with an offset, we could specify the offset before the LIMIT count:
`SELECT * FROM logins LIMIT 1, 2;`

To filter our results we can use WHERE like:
`SELECT * FROM logins WHERE id > 1;`

We can also use LIKE to get records that match a certain pattern:
`SELECT * FROM logins WHERE username LIKE 'admin%';`

% acts a wild card so any record with a username starting in admin will be returned.

We can also use _ as a way to match anyone character:
`SELECT * FROM logins WHERE username like '___';`

This would return any record that is only 3 characters long.

The question for this section is:
What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01? 

To solve this we can run `select * from employees where first_name LIKE 'Bar%' ORDER BY hire_date DESC;`

## SQL Operators

# SQL Injections

## Intro to SQL Injections

## Subverting Query Logic

## Using Comments

## Union Clause

## Union Injection

# Exploitation

## Database Enumeration

## Reading Files

## Writing Files

# Mitigation

## Mitigation SQL Injections

# Closing it Out

## Skills Assessment
