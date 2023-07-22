#! /usr/bin/env python3

# python
import sys
import io
import gzip
import sqlite3
import hashlib

# pypi
import lxml.etree

# local
import base_n



# globals
connection = None
cursor = None



# "B" hashing algo
# https://www.mediawiki.org/wiki/Manual:Resetting_passwords#Direct_database_modification
# var/www/mediawiki-1.40.0/w/includes/password/MWSaltedPassword.php
def get_password_hash(password):
    salt = "1234"
    password = hashlib.md5(password.encode("utf8")).hexdigest()
    password = f"{salt}-{password}"
    password = hashlib.md5(password.encode("utf8")).hexdigest()
    password = f":B:{salt}:{password}"
    return password
    # password: adminadmin25
    # hash: :B:1234:6b8f4d9c838c8808eaf655354351f5f8 (wrong!!)
    # hash: :B:1234:01da5c77a0682a481d4f1c7f115162a1



class User:
    id = 0
    name = ""
    editcount = 0
    password_hash = ""
    def __init__(self, id, name):
        self.id = id
        self.name = name
        # set password to username
        # mediawiki will show a warning on login:
        #   Your password is not valid:
        #   - Passwords must be at least 10 characters.
        #   - Your password must not appear within your username.
        #   Please choose a new password now, or click "Skip" to change it later.
        self.password_hash = get_password_hash(name)



users = {
    "MediaWiki default": User(0),
}



def parse_xml_stream(xml_stream, ignore_default_ns=True):
    """
    ignore_default_ns:
    ignore the default namespace of the root node.

    by default, lxml.etree.iterparse
    returns the namespace in every element.tag.

    with ignore_default_ns=True,
    element.tag returns only the element's localname,
    without the namespace.

    example:
    xml_string:
        <html xmlns="http://www.w3.org/1999/xhtml">
            <div>hello</div>
        </html>
    with ignore_default_ns=False:
        element.tag = "{http://www.w3.org/1999/xhtml}div"
    with ignore_default_ns=True:
        element.tag = "div"

    see also:
    Python ElementTree module: How to ignore the namespace of XML files
    https://stackoverflow.com/a/76601149/10440128
    """

    # save the original read method
    xml_stream_read = xml_stream.read

    if ignore_default_ns:
        def xml_stream_read_track(_size):
            # ignore size, always return 1 byte
            # so we can track node positions
            return xml_stream_read(1)
        xml_stream.read = xml_stream_read_track

    def get_parser(stream):
        return lxml.etree.iterparse(
            stream,
            events=('start', 'end'),
            remove_blank_text=True,
            huge_tree=True,
        )

    if ignore_default_ns:
        # parser 1
        parser = get_parser(xml_stream)

        # parse start of root node
        event, element = next(parser)
        #print(xml_stream.tell(), event, element)
        # get name of root node
        root_name = element.tag.split("}")[-1]
        #print("root name", root_name)
        #print("root pos", xml_stream.tell()) # end of start-tag
        # attributes with namespaces
        #print("root attrib", element.attrib)
        handle_root_start(element)

        # patched document header without namespaces
        xml_stream_nons = io.BytesIO(b"\n".join([
            #b"""<?xml version="1.0" encoding="utf-8"?>""",
            b"<" + root_name.encode("utf8") + b"><dummy/>",
        ]))
        xml_stream.read = xml_stream_nons.read

    # parser 2
    parser = get_parser(xml_stream)

    # parse start of root node
    # note: if you only need "end" events,
    # then wait for end of dummy node
    event, element = next(parser)
    print(event, element.tag)
    assert event == "start"

    if ignore_default_ns:
        assert element.tag == root_name

        # parse start of dummy node
        event, element = next(parser)
        #print(event, element.tag)
        assert event == "start"
        assert element.tag == "dummy"

        # parse end of dummy node
        event, element = next(parser)
        #print(event, element.tag)
        assert event == "end"
        assert element.tag == "dummy"

        # restore the original read method
        xml_stream.read = xml_stream_read

        # now all elements come without namespace
        # so element.tag is the element's localname

    # handle events

    #for i in range(5):
    #    event, element = next(parser)
    #    print(event, element)

    #for event, element in parser:
    #    print(event, element.tag)

    # <siteinfo> appears only once, on start of stream
    for event, element in parser:
        #print(event, repr(element.tag))
        #sys.exit()
        #if event[0] == 'e' and element.tag.endswith('siteinfo'):
        if event[0] == 'e' and element.tag == 'siteinfo':
            handle_siteinfo_end(element)
            element.clear()
            while element.getprevious() is not None:
                del element.getparent()[0]
            break # stop after the first <siteinfo>

    # <page> elements until end of stream
    num_done = 0 # debug
    for event, element in parser:
        #if event[0] == 'e' and element.tag.endswith('page'):
        if event[0] == 'e' and element.tag == 'page':
            handle_page_end(element)
            element.clear()
            while element.getprevious() is not None:
                del element.getparent()[0]
            # debug
            num_done += 1
            if num_done > 10:
                break

    handle_root_end()



class Wikiinfo:
    lang = "en"
wikiinfo = None



def handle_root_start(root):
    #global wikiinfo
    global cursor
    #print("root attributes", root.attrib)

    version = root.attrib["version"]
    assert version == "0.10"

    schemaLocation = root.attrib["{http://www.w3.org/2001/XMLSchema-instance}schemaLocation"]
    assert schemaLocation == "http://www.mediawiki.org/xml/export-0.10/ http://www.mediawiki.org/xml/export-0.10.xsd"

    lang = root.attrib["{http://www.w3.org/XML/1998/namespace}lang"]

    # void openMediaWiki(Attributes attributes)
    #wikiinfo = Wikiinfo()
    # TODO allow missing lang, default is "en"
    #wikiinfo.Lang = lang

    # mwdumper/src/org/mediawiki/dumper/writers/sql/SqlWriter.java
    # public void writeStartWiki(Wikiinfo info)

    print(f"mediawiki dump: version={version} lang={lang}")

    cursor.execute(f"PRAGMA foreign_keys = OFF")

    # https://www.sqlite.org/lang_altertable.html
    # https://www.sqlite.org/lang_transaction.html
    # EXCLUSIVE prevents other database connections from reading the database
    print("starting transaction")
    cursor.execute(f"BEGIN EXCLUSIVE")
    # https://www.mediawiki.org/wiki/Manual:MWDumper
    # The tables page, revision, text must be empty for a successful import.

    db_indices = []
    for name, sql in cursor.execute("SELECT name, sql FROM sqlite_schema WHERE type='index' AND (tbl_name='page' OR tbl_name='revision')"):
        db_indices.append((name, sql))

    # Temporarily remove all indexes and auto_increment fields
    # from the following tables: page, revision and text.
    # This gives a tremendous speed bump,
    # because MySQL will otherwise be updating these indexes after each insert.
    # Don't forget to recreate the indexes afterwards.
    print("dropping indices")
    for name, sql in db_indices:
        cursor.execute(f"DROP INDEX {name}")

    delete_tables = [
        "comment",
        "slots",
        "site_stats",
        "content",
        "querycachetwo",
        "querycache_info",
        "revision_comment_temp",
        "text",
        "recentchanges",
        "page",
        "user",
        "revision",
        "searchindex_content",
        "searchindex_segdir",
        "sqlite_sequence",
    ]

    print("deleting table contents")
    for name in delete_tables:
        # https://www.sqlite.org/lang_delete.html
        # When the WHERE clause and RETURNING clause
        # are both omitted from a DELETE statement
        # and the table being deleted has no triggers,
        # SQLite uses an optimization to erase the entire table content
        # without having to visit each row of the table individually.
        # This "truncate" optimization makes the delete run much faster.
        # [the mediawiki sqlite schema has no triggers.]
        cursor.execute(f"DELETE FROM {name}")

    # limitation:
    # sqlite cannot drop primary keys: page_id, rev_id, old_id
    # mysql:
    # ALTER TABLE page
    #   CHANGE page_id page_id INTEGER UNSIGNED,
    #   DROP INDEX name_title,
    #   DROP INDEX page_random,
    #   DROP INDEX page_len,
    #   DROP INDEX page_redirect_namespace_len;
    # ALTER TABLE revision 
    #   CHANGE rev_id rev_id INTEGER UNSIGNED,
    #   DROP INDEX rev_page_id,
    #   DROP INDEX rev_timestamp,
    #   DROP INDEX page_timestamp,
    #   DROP INDEX user_timestamp,
    #   DROP INDEX usertext_timestamp,
    #   DROP INDEX page_user_timestamp;
    # ALTER TABLE text
    #   CHANGE old_id old_id INTEGER UNSIGNED;



def handle_siteinfo_end(siteinfo):
    global cursor
    # TODO
    print(siteinfo.tag)



def handle_page_end(page):
    global cursor
    global users

    #   <page>
    #     <title>Main Page</title>
    #     <ns>0</ns>
    #     <id>1</id>

    page_id = int(page.find("id").text)
    page_namespace = int(page.find("ns").text)
    page_title = page.find("title").text

    # CREATE TABLE IF NOT EXISTS "page" (
    #  page_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    #  page_namespace INTEGER NOT NULL,
    #  page_title BLOB NOT NULL,
    #  page_is_redirect INTEGER  DEFAULT 0 NOT NULL,
    #  page_is_new INTEGER  DEFAULT 0 NOT NULL,
    #  page_random REAL NOT NULL,
    #  page_touched BLOB NOT NULL,
    #  page_links_updated BLOB DEFAULT NULL,
    #  page_latest INTEGER  NOT NULL,
    #  page_len INTEGER  NOT NULL,
    #  page_content_model BLOB DEFAULT NULL,
    #  page_lang BLOB DEFAULT NULL
    #  );
    # add page:
    # INSERT INTO page VALUES(6,0,'Main_Page',0,0,0.42617357306300002184,'20230703101112','20230703101112',428,46,'wikitext',NULL);
    sql = "INSERT INTO page (page_id, page_namespace, page_title) VALUES (?, ?, ?)"
    args = (page_id, page_namespace, page_title)
    cursor.execute(sql, args)



    previous_revision_id = 0
    previous_revision_timestamp = ""
    previous_revision_text_length = 0

    for revision in page.findall("revision"):

        #     <revision>
        #       <id>1</id>
        #       <timestamp>2017-06-02T15:50:38Z</timestamp>
        #       <contributor>
        #         <username>MediaWiki default</username>
        #         <id>0</id>
        #       </contributor>
        #       <model>wikitext</model>
        #       <format>text/x-wiki</format>
        #       <text xml:space="preserve" bytes="717">&lt;strong&gt;MediaWiki has been installed.&lt;/strong&gt;

        revision_model = revision.find("model").text
        assert revision_model == "wikitext"

        revision_format = revision.find("format").text
        assert revision_format == "text/x-wiki"

        revision_id = int(revision.find("id").text)
        revision_parent_id = previous_revision_id

        revision_text = revision.find("text").text
        revision_text_sha1 = base_n.to_base(int(hashlib.sha1(revision_text.encode("utf8")).hexdigest(), 16), 36)
        revision_text_length = len(revision_text)

        # a: 2017-06-02T15:50:38Z
        # a: 20170602155038
        # string.translate(table, deletechars=None)
        revision_timestamp = revision.find("timestamp").text
        revision_timestamp = revision_timestamp.translate(None, "-T:Z")
        assert len(revision_timestamp) == 14, f"invalid revision_timestamp: {repr(revision_timestamp)}"

        revision_minor_edit = 1 if revision.find("minor") else 0

        # deleted pages do not appear in the XML dump
        revision_deleted = 0

        contributor = revision.find("contributor")
        user_name = contributor.find("username").text
        user_id = int(contributor.find("id").text)
        if not user_name in users:
            users[user_name] = User(user_id)
        users[user_name].editcount += 1

        # CREATE TABLE IF NOT EXISTS "text" (
        #  old_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        #  old_text BLOB NOT NULL, old_flags BLOB NOT NULL
        #  );
        # INSERT INTO text VALUES(425,replace('some text\n\n== some heading ==\n\nmore text\n\nedit','\n',char(10)),'utf-8');
        cursor.execute("INSERT INTO text (old_text, old_flags) VALUES (?, 'utf-8')", (revision_text,))
        revision_text_id = cursor.lastrowid

        # CREATE TABLE IF NOT EXISTS "content" (
        #  content_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        #  content_size INTEGER  NOT NULL,
        #  content_sha1 BLOB NOT NULL, content_model INTEGER  NOT NULL,
        #  content_address BLOB NOT NULL
        #  );
        # INSERT INTO content VALUES(425,46,'1rvbsfm5kgn4b9fouq5bd0rzkyuod5h',1,'tt:425');
        sql = "INSERT INTO content (content_size, revision_text_sha1, content_address) VALUES (?, ?, ?)"
        # sha1 is stored in base36
        args = (revision_text_length, revision_text_sha1, f"tt:{revision_text_id}")
        cursor.execute(sql, args)
        content_id = cursor.lastrowid

        # CREATE TABLE IF NOT EXISTS "comment" (
        #  comment_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        #  comment_hash INTEGER NOT NULL,
        #  comment_text BLOB NOT NULL,
        #  comment_data BLOB DEFAULT NULL
        #  );
        # INSERT INTO comment VALUES(270,27680485,'edit summary',NULL);
        # >>> zlib.crc32("edit summary".encode("utf8"))
        # 27680485
        comment_id = 0 # default: no comment
        if comment_text != "":
            sql = "INSERT INTO comment (comment_hash, comment_text) VALUES (?, ?)"
            args = (zlib.crc32(comment_text.encode("utf8")), comment_text)
            cursor.execute(sql, args)
            comment_id = cursor.lastrowid

        # CREATE TABLE IF NOT EXISTS "revision" (
        #  rev_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        #  rev_page INTEGER  NOT NULL,
        #  rev_comment_id INTEGER  DEFAULT 0 NOT NULL,
        #  rev_actor INTEGER  DEFAULT 0 NOT NULL,
        #  rev_timestamp BLOB NOT NULL,
        #  rev_minor_edit INTEGER  DEFAULT 0 NOT NULL,
        #  rev_deleted INTEGER  DEFAULT 0 NOT NULL,
        #  rev_len INTEGER  DEFAULT NULL,
        #  rev_parent_id INTEGER  DEFAULT NULL,
        #  rev_sha1 BLOB DEFAULT '' NOT NULL
        #  );
        # INSERT INTO revision VALUES(428,6,0,1,'20230703101112',0,0,46,427,'1rvbsfm5kgn4b9fouq5bd0rzkyuod5h');
        # all columns:
        # (rev_id, rev_page, rev_comment_id, rev_actor, rev_timestamp,
        # rev_minor_edit, rev_deleted, rev_len, rev_parent_id, rev_sha1)
        sql = "INSERT INTO revision VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        args = (
            revision_id, page_id, comment_id, user_id, revision_timestamp,
            revision_minor_edit, revision_deleted, revision_text_length,
            revision_parent_id, revision_text_sha1,
        )
        cursor.execute(sql, args)
        #revision_id = cursor.lastrowid

        # INSERT INTO revision_comment_temp VALUES(428,270);
        sql = "INSERT INTO revision_comment_temp VALUES (?, ?)"
        args = (revision_id, comment_id)
        cursor.execute(sql, args)

        # CREATE TABLE IF NOT EXISTS "recentchanges" (
        #  rc_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, -- 1
        #  rc_timestamp BLOB NOT NULL,
        #  rc_actor INTEGER  NOT NULL,
        #  rc_namespace INTEGER DEFAULT 0 NOT NULL,
        #  rc_title BLOB DEFAULT '' NOT NULL, -- 5
        #  rc_comment_id INTEGER  NOT NULL,
        #  rc_minor INTEGER  DEFAULT 0 NOT NULL,
        #  rc_bot INTEGER  DEFAULT 0 NOT NULL,
        #  rc_new INTEGER  DEFAULT 0 NOT NULL,
        #  rc_cur_id INTEGER  DEFAULT 0 NOT NULL, -- 10
        #  rc_this_oldid INTEGER  DEFAULT 0 NOT NULL,
        #  rc_last_oldid INTEGER  DEFAULT 0 NOT NULL,
        #  rc_type INTEGER  DEFAULT 0 NOT NULL,
        #  rc_source BLOB DEFAULT '' NOT NULL,
        #  rc_patrolled INTEGER  DEFAULT 0 NOT NULL,
        #  rc_ip BLOB DEFAULT '' NOT NULL,
        #  rc_old_len INTEGER DEFAULT NULL,
        #  rc_new_len INTEGER DEFAULT NULL,
        #  rc_deleted INTEGER  DEFAULT 0 NOT NULL,
        #  rc_logid INTEGER  DEFAULT 0 NOT NULL,
        #  rc_log_type BLOB DEFAULT NULL,
        #  rc_log_action BLOB DEFAULT NULL,
        #  rc_params BLOB DEFAULT NULL
        #  );
        # INSERT INTO recentchanges VALUES(2,'20230703101112',1,0,'Main_Page',270,0,0,0,6,428,427,0,'mw.edit',2,'127.0.0.1',40,46,0,0,NULL,'','');
        sql = "INSERT INTO recentchanges (rc_timestamp, rc_actor, rc_namespace, rc_title, rc_comment_id) VALUES (?, ?)"
        args = (revision_id, comment_id)
        cursor.execute(sql, args)

        # CREATE TABLE IF NOT EXISTS "slots" (
        #  slot_revision_id INTEGER  NOT NULL,
        #  slot_role_id INTEGER  NOT NULL,
        #  slot_content_id INTEGER  NOT NULL,
        #  slot_origin INTEGER  NOT NULL,
        #  PRIMARY KEY(slot_revision_id, slot_role_id)
        #  );
        # INSERT INTO slots VALUES(428,1,425,428);
        args = (revision_id, role_id, content_id, origin_id)
        cursor.execute("INSERT INTO slots VALUES (?, ?, ?, ?)", args)

        # CREATE TABLE IF NOT EXISTS "page" (
        #  page_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        #  page_namespace INTEGER NOT NULL, page_title BLOB NOT NULL,
        #  page_is_redirect INTEGER  DEFAULT 0 NOT NULL,
        #  page_is_new INTEGER  DEFAULT 0 NOT NULL,
        #  page_random REAL NOT NULL,
        #  page_touched BLOB NOT NULL, page_links_updated BLOB DEFAULT NULL,
        #  page_latest INTEGER  NOT NULL,
        #  page_len INTEGER  NOT NULL,
        #  page_content_model BLOB DEFAULT NULL,
        #  page_lang BLOB DEFAULT NULL
        #  );

        # add revision:
        # REPLACE INTO page VALUES(6,0,'Main_Page',0,0,0.42617357306300002184,'20230703101112','20230703101112',428,46,'wikitext',NULL);
        # REPLACE INTO user VALUES(1,'Admin','',':pbkdf2:sha512:30000:64:f9hdMMgsfHMwSFpkokPysg==:rN+3rH1/gCrODn+xdLv+fMxiFehifh8BVfE4AJoiyaTmZwoC81sinIUmA69iLEXOM9i5f0+TVIiFjIB0Dpu2Yw==','',NULL,'','20230702100425','306c13f21345a31455bbd4fc18c8a328',NULL,'',NULL,'20230702100424',2,NULL);

        previous_revision_id = revision_id
        previous_revision_timestamp = revision_timestamp
        previous_revision_text_length = revision_text_length



    # CREATE TABLE IF NOT EXISTS "page" (
    #  page_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    #  page_namespace INTEGER NOT NULL,
    #  page_title BLOB NOT NULL,
    #  page_is_redirect INTEGER  DEFAULT 0 NOT NULL,
    #  page_is_new INTEGER  DEFAULT 0 NOT NULL,
    #  page_random REAL NOT NULL,
    #  page_touched BLOB NOT NULL,
    #  page_links_updated BLOB DEFAULT NULL,
    #  page_latest INTEGER  NOT NULL,
    #  page_len INTEGER  NOT NULL,
    #  page_content_model BLOB DEFAULT NULL,
    #  page_lang BLOB DEFAULT NULL
    #  );
    # update page

    #  page_touched BLOB NOT NULL,
    #  page_links_updated BLOB DEFAULT NULL,
    #  page_latest INTEGER  NOT NULL,
    #  page_len INTEGER  NOT NULL,

    sql = "UPDATE page SET page_touched = ?, page_links_updated = ?, page_latest = ?, page_len = ? WHERE page_id = ?"
    args = (
        previous_revision_timestamp,
        previous_revision_timestamp,
        previous_revision_id,
        previous_revision_text_length,
        page_id,
    )
    cursor.execute(sql, args)



    # mwdumper/src/org/mediawiki/dumper/writers/sql/SqlWriter1_25.java
    # bufferInsertRow("page", new Object[][] {
    #         {"page_id", new Integer(page.Id)},
    #         {"page_namespace", page.Title.Namespace},
    #         {"page_title", titleFormat(page.Title.Text)},
    #         {"page_restrictions", page.Restrictions},
    #         {"page_is_redirect", page.isRedirect ? ONE : ZERO},
    #         {"page_is_new", ZERO},
    #         {"page_random", traits.getRandom()},
    #         {"page_touched", traits.getCurrentTime()},
    #         {"page_latest", new Integer(revision.Id)},
    #         {"page_len", revision.Bytes},
    #         {"page_content_model", revision.Model},

    # CREATE TABLE IF NOT EXISTS "page" (
    #  page_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    #  page_namespace INTEGER NOT NULL, page_title BLOB NOT NULL,
    #  page_is_redirect INTEGER  DEFAULT 0 NOT NULL,
    #  page_is_new INTEGER  DEFAULT 0 NOT NULL,
    #  page_random REAL NOT NULL,
    #  page_touched BLOB NOT NULL, page_links_updated BLOB DEFAULT NULL,
    #  page_latest INTEGER  NOT NULL,
    #  page_len INTEGER  NOT NULL,
    #  page_content_model BLOB DEFAULT NULL,
    #  page_lang BLOB DEFAULT NULL
    #  );

    # select name from sqlite_schema where type='table';
    # select name from sqlite_schema where type='table' and name like 'page%';


    keys = [
        ("page_id", page.find("id").text),
        ("page_namespace", page.find("ns").text),
        ("page_is_redirect", xxx),
        ("page_is_new", xxx),
        ("page_random", xxx),
        ("page_touched", xxx),
        ("page_latest", xxx),
        ("page_len", xxx),
        ("page_content_model", xxx),
        ("page_lang", xxx),
    ]
    #cursor.execute("INSERT INTO page VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,)")

    # mwdumper/src/org/mediawiki/dumper/writers/sql/SqlWriter14.java
    # mwdumper/src/org/mediawiki/dumper/writers/sql/SqlWriter15.java
    sys.exit()



def handle_root_end():
    global cursor

    print("inserting users")
    # TODO sort by user id
    for user in users.values():
        sql = "INSERT INTO user(user_id,user_name,user_password,user_editcount) VALUES(?,?,?,?,?)"
        args = (user.id, user.name, user.password, user.editcount)
        cursor.execute(sql, args):

    print("creating indices")
    for name, sql in db_indices:
        # CREATE INDEX ...
        cursor.execute(sql)

    print("closing transaction")
    cursor.execute("COMMIT")

    print("TODO https://www.mediawiki.org/wiki/Manual:Rebuildall.php")



def main(argv):
    global connection
    global cursor
    #connection = sqlite3.connect("my_wiki.sqlite")
    #cursor = connection.cursor()

    # dummy cursor
    class DummyCursor:
        def execute(self, sql):
            print(sql)
            return []
    cursor = DummyCursor()

    with gzip.open("wikidump.xml.gz", "rb") as xml_file:
        parse_xml_stream(xml_file)



if __name__ == "__main__":
    main(sys.argv)



# dead code

if False:

    print("xml_stream.tell 1", xml_stream.tell())

    while char := xml_stream.read(1):
        if char != b"<":
            continue
        break
    buf = b"<"
    # <mediawiki>
    while char := xml_stream.read(1):
        buf += char
        if char != b">":
            continue
        print("mediawiki element:", repr(buf))
        break
    # <siteinfo>, <page>...

    print("xml_stream.tell 2", xml_stream.tell())

    fake_xml_stream = io.BytesIO(b"<mediawiki><dummy/>") # start of root node without namespace
    xml_stream_read = xml_stream.read # backup
    xml_stream.read = fake_xml_stream.read # patch

    parser = lxml.etree.iterparse(
        xml_stream,
        events=('start', 'end'),
        remove_blank_text=True,
        huge_tree=True,
    )

    # <dummy> is the first element
    event, element = next(parser)
    assert event == "start"
    assert element.tag == "mediawiki"

    event, element = next(parser)
    assert event == "start"
    assert element.tag == "dummy"

    event, element = next(parser)
    assert event == "end"
    assert element.tag == "dummy"

    xml_stream.read = xml_stream_read # restore
