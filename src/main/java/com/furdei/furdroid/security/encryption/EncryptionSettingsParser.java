package com.furdei.furdroid.security.encryption;

import android.content.Context;

import org.xmlpull.v1.XmlPullParser;

import java.util.HashMap;
import java.util.Map;


/**
 * Parses encryption settings from XML
 *
 * @author Stepan Furdey
 */
public class EncryptionSettingsParser implements EncryptionSettingsProvider {

    private XmlPullParser parser;

    public EncryptionSettingsParser(XmlPullParser parser) {
        this.parser = parser;
    }

    public EncryptionSettingsParser(Context context, int settingsXmlResourceId) {
        this(context.getResources().getXml(settingsXmlResourceId));
    }

    private static final String ENCRYPTION_TAG = "encryption";
    private static final String TABLE_TAG      = "table";
    private static final String COLUMN_TAG     = "column";
    private static final String NAME_ATTRIBUTE = "name";

    private static final String ENCRYPTION_TAG_EXPECTED = "<encryption> tag is expected";
    private static final String TABLE_TAG_EXPECTED      = "<table> tag is expected";
    private static final String COLUMN_TAG_EXPECTED     = "<column> tag is expected";
    private static final String TABLE_MUST_HAVE_NAME    = "<table> tag must have 'name' attribute";
    private static final String COLUMN_MUST_HAVE_NAME   = "<column> tag must have 'name' attribute";
    private static final String NAME_IS_EMPTY           = "'name' attribute is empty";

    /**
     * {@inheritDoc}
     */
    @Override
    public EncryptionSettings getEncryptionSettings() {
        try {
            Map<String, EncryptedTableSettings> encTables = new HashMap<String, EncryptedTableSettings>();
            boolean found = false;

            while (!found && parser.getEventType() != XmlPullParser.END_DOCUMENT) {
                parser.next();
                found = parser.getEventType() == XmlPullParser.START_TAG && ENCRYPTION_TAG.equals(parser.getName());
            }

            if (!found) {
                throw new IllegalStateException(ENCRYPTION_TAG_EXPECTED);
            }

            while (parser.nextTag() != XmlPullParser.END_TAG) {
                // <table> tag cycle
                String tagName = parser.getName();
                if (!TABLE_TAG.equals(tagName)) {
                    throw new IllegalStateException(TABLE_TAG_EXPECTED);
                }

                int attrsCount = parser.getAttributeCount();
                if (attrsCount != 1) {
                    throw new IllegalStateException(TABLE_MUST_HAVE_NAME);
                }

                String attrName = parser.getAttributeName(0);
                if (!NAME_ATTRIBUTE.equals(attrName)) {
                    throw new IllegalStateException(TABLE_MUST_HAVE_NAME);
                }

                String tableName = parser.getAttributeValue(0);
                if (tableName == null || tableName.trim().length() == 0) {
                    throw new IllegalStateException(NAME_IS_EMPTY);
                }

                EncryptedTableSettings encTable = new EncryptedTableSettings(tableName);

                while (parser.nextTag() != XmlPullParser.END_TAG) {
                    // <column> tag cycle
                    tagName = parser.getName();
                    if (!COLUMN_TAG.equals(tagName)) {
                        throw new IllegalStateException(COLUMN_TAG_EXPECTED);
                    }

                    attrsCount = parser.getAttributeCount();
                    if (attrsCount != 1) {
                        throw new IllegalStateException(COLUMN_MUST_HAVE_NAME);
                    }

                    attrName = parser.getAttributeName(0);
                    if (!NAME_ATTRIBUTE.equals(attrName)) {
                        throw new IllegalStateException(COLUMN_MUST_HAVE_NAME);
                    }

                    String name = parser.getAttributeValue(0);
                    if (name == null || name.trim().length() == 0) {
                        throw new IllegalStateException(NAME_IS_EMPTY);
                    }

                    encTable.markColumnEncrypted(name);
                    parser.nextTag(); // </column>
                }

                encTables.put(tableName, encTable);
            }

            EncryptionSettings encryptionSettings = new EncryptionSettings();
            encryptionSettings.setEncryptedTables(encTables);

            return encryptionSettings;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error while parsing encryption settings", e);
        }
    }

}
