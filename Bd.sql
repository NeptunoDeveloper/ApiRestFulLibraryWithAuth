CREATE TABLE Authors
(
Id_Author NUMERIC(10,0),
Name VARCHAR (30),
Last_Name VARCHAR(30),
Email VARCHAR(30),
CONSTRAINT PK_Author PRIMARY KEY (Id_Author)
);

CREATE TABLE Books
(
Id_Book NUMERIC(10,0),
Id_Author NUMERIC(10,0) NULL,
Title VARCHAR(30),
Description VARCHAR(200),
Section VARCHAR(20),
Genre VARCHAR(30),
Year INT,
Publisher VARCHAR(30),
CONSTRAINT PK_Book PRIMARY KEY (Id_Book),
CONSTRAINT FK_BooksAuthors FOREIGN KEY (Id_Author) REFERENCES Authors(Id_Author)
);
																 
																 
INSERT INTO Authors(Id_Author, Name,Last_Name,Email) VALUES(50001,'Jane','Austen','j.austey@gmail.com');

INSERT INTO Authors (Id_Author, Name,Last_Name,Email) VALUES(50002,'Paulo','Coelho','p.coelho@gmail.com');

INSERT INTO Authors(Id_Author, Name,Last_Name,Email) VALUES(50003,'William','Goldman','w.goldman@gmail.com');

INSERT INTO Authors(Id_Author, Name,Last_Name,Email) VALUES(50004,'Miguel','Cervantes','m.cervantes@gmail.com');


INSERT INTO Books
(Id_Book, Id_Author,Title,Description,Section,Genre,Year,Publisher)
VALUES(1,50003,'The princess bride','The book combines elements of comedy and romance','Family','Romance','1973','Londom-Books');

INSERT INTO Books
(Id_Book, Id_Author,Title,Description,Section,Genre,Year,Publisher)
VALUES
(2,50001,'Pride and Perjudice','Pride and Prejudice is a romantic novel by Jane Austen, first published in 1813.','Adults',
'Romance','1813','Thomas Egerton');

INSERT INTO Books
(Id_Book, Id_Author,Title,Description,Section,Genre,Year,Publisher)
VALUES(3,50004,'Sir Quixote of La Mancha','Is a Spanish novel by Miguel de Cervantes Saavedra. ',
'Adventure','Novel','1605','Francisco de Robles');

INSERT INTO Books
(Id_Book, Id_Author,Title,Description,Section,Genre,Year,Publisher)
VALUES(4,50004,'Don quijote de la Mancha','Novela mas influyente en la lengua española ',
'Adventura','Novela','1605','Francisco de Robles');


INSERT INTO Books
(Id_Book, Id_Author,Title,Description,Section,Genre,Year,Publisher)
VALUES(5,50002,'The darkest forest','Is a novel by Brazilian author Paulo Coelho which was first published in 1988. ',
'Adults','Fear','1988','Bright-Books');

