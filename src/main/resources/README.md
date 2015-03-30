# Secure Storage

![Secure Storage Logo](http://www.furdei.systems/img/portfolio/security.jpg "Secure Storage Logo")

**Furdroid-security** is helpful if you want to implement
a secure Android storage. **Furdroid** provides you with a set of components to work with encrypted
database and file storage. You still work with SQLite database but it's content is encrypted. You
can configure which tables and which columns should be encrypted. **Furdroid** will also help you to
generate key and store it in a secure manner.

## Before you start

Before you start using **furdroid** please make sure you have an Android artifact 'android:android'
in your local Maven repository. If you don't please visit
[maven-android-sdk-deployer](https://github.com/simpligility/maven-android-sdk-deployer)
project and follow the instruction.

## Maven Dependency

```xml
<dependency>
  <groupId>systems.furdei</groupId>
  <artifactId>furdroid-security</artifactId>
  <version>${project.version}</version>
</dependency>
```

## Gradle Dependency

```groovy
dependencies {
  compile 'systems.furdei:furdroid-security:${project.version}'
}

```

## Description

EncryptionUtils class provides core utility methods to implement encryption and decryption for Android
applications' data. It provides support for symmetric encryption algorithm AES. That means
it uses for decryption the same key used for encryption. It is highly unsafe to store a key
on device or obtain it elsewhere if hacker can reproduce these steps to obtain a key. That's
why the key isn't stored anywhere but is generated on the fly. The problem is that key
derivation algorithm also has to be secure. It is solved by adding a variable to the algorithm:
a text password that you shouldn't keep on the device but make user enter every time he launches
an application. It decreases usability but keeps security high. If a hacker doesn't get a
password, he wouldn't be able to derive a key and decrypt your data. From the other side, key
derivation algorithm guarantees that the same key will always be generated from the same
password, so that you don't ever have to save a key on the device.

### Initialize encryption

Basically to initialize EncryptionUtils you should call only two methods:
setPassword(String) to specify a password for key derivation and
setEncryptionSettingsProvider(EncryptionSettingsProvider) to specify what tables you
want to encrypt in your database. Note that you don't need to call
setEncryptionSettingsProvider(EncryptionSettingsProvider) if you don't use SQLite
database in your application. If you want only to access a secure file storage than setting
a password is everything you need to initialize encryption.

### Accessing secure file storage

This library provides a number of convenient APIs to access secure storage through
EncryptedFileStorage.readXXX and EncryptedFileStorage.writeXXX methods.
See EncryptedFileStorage for details.

### Accessing secure database

To work with encrypted SQLite database you should first setup database encryption settings.
You need to provide an instance of EncryptionSettingsProvider to a static method
setEncryptionSettingsProvider(EncryptionSettingsProvider). You can crate your own
provider or use an out-of-the-box implementation EncryptionSettingsParser. It reads encryption
settings out of XML file you specify. An example of XML encryption settings (encryption_settings.xml):

```xml
<?xml version="1.0" encoding="utf-8"?>
<encryption>
     <table name="payments">
         <column name="account_from" />
         <column name="description" />
     </table>
     <table name="customers">
         <column name="address" />
         <column name="phone" />
     </table>
</encryption>
```

Now you only need to call setEncryptionSettingsProvider(EncryptionSettingsProvider) to finish the setup:

```java
 EncryptionUtils.setEncryptionSettingsProvider(
     new EncryptionSettingsParser(getApplicationContext(), R.xml.encryption_settings));
```

In the above example we specify that we want to encrypt tables *payments* and
*customers*. But we don't usually need to encrypt the whole table, only some
sensible piece of data. In our case only an account number and description would be encrypted
for payments and some contact information of our customers also. You don't need to encrypt
all your data for several reasons.

First of all, you are running your application on a slow mobile device and you don't want to
increase time of waiting for data access operations to complete. Software encryption affects
performance dramatically.

The second reason is that encryption makes database search operations impossible. You have to
work around, possibly create new columns containing some functions over the original data to
keep sorting order etc. So you basically need to encrypt only top secret piece of data that
should be as small as possible.

### Encrypting data to save into SQLite database

Assuming you have already got contentValues - an unencrypted instance of
ContentValues class and you want to insert a new payment into table
*payments*. Typical steps to encrypt data:
--* Set a password and encryption settings as described above once per app launch.
--* Initialize a *Cipher* instance for encryption:
```java
Cipher cipher = EncryptionUtils.initForEncrypt();
```
--* Call EncryptionUtils.encryptContentValues(Cipher, ContentValues, String):
```java
EncryptionUtils.encryptContentValues(cipher, contentValues, "payments");
```

That's it. Now you can insert or update records using encrypted data.

The important thing to point out is that **data types can change during encryption**. All
encrypted data are represented by Base64-encoded strings even if the original data was integer
or float or any other data type. Make sure that you have *TEXT* type of encrypted
columns in your database.

### Decrypting data read from SQLite database

SQLite data reading is implemented through the cursors. This library provides a special cursor
type DecryptingSQLiteCursor with support for decryption on the fly. To make SQLite database create and return
DecryptingSQLiteCursor cursors you need to set up a cursor factory
DecryptingSQLiteCursorFactory when you create an SQLiteOpenHelper instance:

```java
 SQLiteDatabase.CursorFactory cursorFactory = new DecryptingSQLiteCursorFactory();
 SQLiteOpenHelper helper = new SQLiteOpenHelper(
     getContext(), DATABASE_NAME, cursorFactory, DATABASE_VERSION) {
         // ...
     };
```

## furdroid

**Furdroid-components** is distributed as a part of [furdroid](https://github.com/furdei/furdroid) project.
Follow [this link](https://github.com/furdei/furdroid) to find more useful visual components, widgets and database
tools by [furdei.systems](http://www.furdei.systems).
