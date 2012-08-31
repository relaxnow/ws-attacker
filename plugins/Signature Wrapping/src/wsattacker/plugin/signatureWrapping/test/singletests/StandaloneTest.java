package wsattacker.plugin.signatureWrapping.test.singletests;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;
import wsattacker.plugin.signatureWrapping.xpath.wrapping.WrappingOracle;

import java.io.*;
import java.util.List;

import static junit.framework.Assert.assertTrue;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.domToString;

public class StandaloneTest {

    @Test
    public void doItTest() throws FileNotFoundException, SAXException, IOException {
        Logger.getRootLogger().setLevel(Level.ALL);
        BasicConfigurator.configure();

        SignatureManager signatureManager = new SignatureManager();
        signatureManager.setDocument(DomUtilities.readDocument("/tmp/assertion.xml"));
        SchemaAnalyzer usedSchemaAnalyser = new SchemaAnalyzer();

        // TODO: Find better way than hard-coding Schema names...
        final String schemaDir = "plugins/Signature Wrapping/XML Schema";

        File dir = new File(schemaDir);
        File [] schemaFiles = dir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(".xsd");
            }
        });

        for (File schemaFile : schemaFiles)
        {
            Document xsd;
            String filename = schemaFile.getAbsolutePath();

            try
            {
                xsd = DomUtilities.readDocument(new FileInputStream(filename));
            }
            catch (Exception e)
            {
                e.printStackTrace();
                System.err.println("Could not read: " + filename);
                continue;
            }
            usedSchemaAnalyser.appendSchema(xsd);
        }

        String originalContent = "john.doe";
        String payloadContent = "mallory";

        List<OptionPayload> payloads = signatureManager.getPayloads();
        for (OptionPayload optionPayload : payloads)
        {
            String thePayload = domToString(optionPayload.getSignedElement()).replace(originalContent, payloadContent);
            Assert.assertTrue(optionPayload.isValid(thePayload));
            Assert.assertTrue(optionPayload.parseValue(thePayload));
        }

        WrappingOracle wrappingOracle = new WrappingOracle(signatureManager.getDocument(), signatureManager.getPayloads(), usedSchemaAnalyser);

        int signedElements                          = wrappingOracle.getCountSignedElements();
        int elementsByID                            = wrappingOracle.getCountElementsReferedByID();
        int elementsByXPath                         = wrappingOracle.getCountElementsReferedByXPath();
        int elementsByFastXPath                     = wrappingOracle.getCountElementsReferedByFastXPath();
        int elementsByPrefixfreeTransformedFastXPath= wrappingOracle.getCountElementsReferedByPrefixfreeTransformedFastXPath();
        int maxPossibilities                        = wrappingOracle.maxPossibilities();

        System.out.println("signedElements: " + signedElements);
        System.out.println("elementsByID: " +elementsByID);
        System.out.println("elementsByXpath: " + elementsByXPath);
        System.out.println("elementsByFastXpath: " + elementsByFastXPath);
        System.out.println("elementByPrefixfreeTransformedFastXpath: " + elementsByPrefixfreeTransformedFastXPath);
        System.out.println("maxPossibilities: " + maxPossibilities);
        assertTrue(maxPossibilities > 0);
    }
}
