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

This section just covers common operators (i.e. AND, OR, NOT)

I know all this information already and don't feel like re-documenting it.

The question in this section was:
In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'? 

To get this we can run:
`SELECT * FROM titles where emp_no > 10000 OR title NOT LIKE '%Engineer%';`

The answer was 654

# SQL Injections

## Intro to SQL Injections

There are many types of SQL Injections. Examples include In-Band (which is split into union based and error based), Blind (split into Boolean Based and Time Based), and Out of band.

A SQL injection is when a web application that use SQL in the backend takes input from a user that breaks the expected query in a way that allows the user to perform a different malicious command on the database.

in general this can be avoided by sanatizing input and never trusing user input as is.

An example of a vulnerable command would be:
`$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query)`

In it you can see that the user's input is used directly and not sanatized at all. Alongside this, usually commands like these should be parameterized.

## Subverting Query Logic

This section covers subverting a query by using the OR operator to have a return value always be true.

The example given is the classic SQL injection example `' or '1' = '1`

The example test on this page is a bit silly, we are given a page in which it literally tells us the query being run and exactly how. So subverting it is very easy.

The question on this section is:
Try to log in as the user 'tom'. What is the flag value shown after you successfully log in? 

To do this, we want to enter `tom' or '1' = '1` in the username field and submit. This allows us to log in because the resulting query is true and the tom as a login exists. If it did not it would fail.

## Using Comments

This sections using comments in SQL and how it can be used to subvert sql queries.

There are 3 types of comments in MySQL with --, #, and /**/. But only the first two are usually used in sql injections.

From the previous section we can achieve logging into the page as admin with just `admin'--`

It mentions in this sections its possible to force an evaluation to happen first with parantheses. And this can make it harder to just use the comment to login.

This is still relatively easy to subvert by simply adding a closing brace before your comment.

The question for this section is: 
 Login as the user with the id 5 to get the flag. 

To do this we can enter `') OR id=5 -- ` into the username field. the ') closes the original username check, then we can get the id we want using OR then end it with -- with a space at the end to kill the rest of the query.

## Union Clause

This section covers using a UNION clause to dump whole other tables after a sql query. An example SQL Query using union that gets all the data out of two tables would be `SELECT * FROM ports UNION SELECT * FROM ships;`

But the above query won't always work. A UNION requires both tables to have the same number of columns. So if either of the tables does not this query fails.

To avoid this we can intentionally add false columns to our query to match the same number. The best way to do this is by looking for a NULL column for as many times as we need to match.

The question on this section was:
Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table. 

To solve this I ran `mysql -h 83.136.249.57 -P 32347 -u root -p` to connect to the instance.

Then I ran Select * on both tables and counted the columns. The first had 6 and the second had 2.

So to get the answer I ran `select * from employees UNION select dept_no, dept_name, NULL, NULL, NULL, NULL from departments;`

## Union Injection

This section covers union injection. The first thing it covers is how to determine how many columns we have and how to make sure the output that we want is displayed to the screen. 

There are two ways to do this, we can use the ORDER BY command on each column and when it fails to work we know its one less then the number we tried.

Or we can use the union and just guess the numbers like `cn' UNION select 1,2,3-- -` as we increase this number we will eventually find the failure. An added benefit of this method is it tells us which columns are actually displayed.

The question on this section is:
 Use a Union injection to get the result of 'user()'

The answer is to run `cn' UNION select 1,user(),3,4-- -`

# Exploitation

## Database Enumeration

## Reading Files

## Writing Files

# Mitigation

## Mitigation SQL Injections

# Closing it Out

## Skills Assessment
