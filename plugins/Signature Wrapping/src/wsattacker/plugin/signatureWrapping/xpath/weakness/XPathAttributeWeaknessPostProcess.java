package wsattacker.plugin.signatureWrapping.xpath.weakness;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathWeakness;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.OrExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.Predicate;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.AttributeAndExpression;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;

/**
 * XPathWeakness which adjusts the attribute values of the signed element and the payload element.
 */
public class XPathAttributeWeaknessPostProcess implements XPathWeakness
{
  private Step                         step;
  private static Logger                log = Logger.getLogger(XPathAttributeWeaknessPostProcess.class);
  private List<AttributeAndExpression> attributeAndList;

  public XPathAttributeWeaknessPostProcess(Step step)
                                                     throws InvalidWeaknessException
  {
    attributeAndList = new ArrayList<AttributeAndExpression>();
    for (Predicate pred : step.getPredicates())
      for (OrExpression or : pred.getOrExpressions())
        if (or.getAndExpressions().size() == 1 && or.getAndExpressions().get(0) instanceof AttributeAndExpression)
        {
          AttributeAndExpression and = (AttributeAndExpression) or.getAndExpressions().get(0);
          attributeAndList.add(and);
        }
    if (attributeAndList.isEmpty())
      throw new InvalidWeaknessException("No Attribut-Expressions found.");
  }

  @Override
  public int getNumberOfPossibilites()
  {
    // Basically, there are three possibilites:
    // 1) Payload and Signed Element have the same attribute value
    // 2) Payload gets a new attribute value
    // 3) Remove attribute from payload
    return 3 * attributeAndList.size();
  }

  /**
   * There are 3 possibilites for every attribute.
   */
  @Override
  public void abuseWeakness(int index,
                            Element signedElement,
                            Element payloadElement)
                                                   throws InvalidWeaknessException
  {
    AttributeAndExpression and = attributeAndList.get(index / 3);
    abuseWeakness(and, index % 3, signedElement, payloadElement);
  }

  /**
   * Adjusts the attribute of the affected elements.
   * There are three possibilities:
   * 1) Payload element gets new attribute value.
   * 2) Palyoad element uses the same value as the signed element. 
   * 3) The attribute is removed from the payload element.
   * @param and
   * @param index
   * @param signedElement
   * @param payloadElement
   * @throws InvalidWeaknessException
   */
  private void abuseWeakness(AttributeAndExpression and,
                             int index,
                             Element signedElement,
                             Element payloadElement)
                                                    throws InvalidWeaknessException
  {
    // 1) Detect the affected signed Element
    // /////////////////////////////////////
    int difference = 0;
    Element signedAttributeElement = signedElement;
    Attr signedAttribute = getAttributeByQualifiedName(signedAttributeElement, and.getPrefix(), and.getLocalname());

    while (signedAttributeElement.getNodeType() == Node.ELEMENT_NODE && ((signedAttribute == null) || (signedAttribute != null && !signedAttribute
        .getValue().equals(and.getValue()))))
    {
      ++difference;
      signedAttributeElement = (Element) signedAttributeElement.getParentNode();
      signedAttribute = getAttributeByQualifiedName(signedAttributeElement, and.getPrefix(), and.getLocalname());
    }

    if (signedAttribute == null)
    {
      log.warn("Could not detect signed attribute Element for " + and);
      throw new InvalidWeaknessException();
    }

    // 2) Detect the affected payload Element
    // ///////////////////////////////////////
    Element payloadAttributeElement = payloadElement;
    for (int i = 0; i < difference; ++i)
    {
      payloadAttributeElement = (Element) payloadAttributeElement.getParentNode();
    }

    // 3) Extract the concrete Attribute (if exist)
    // /////////////////////////////////////////////
    Attr payloadAttribute = getAttributeByQualifiedName(payloadAttributeElement, and.getPrefix(), and.getLocalname());

    if (payloadAttribute == null)
    {
      // Clone attribute from signedAttributeElement
      payloadAttribute = (Attr) getAttributeByQualifiedName(signedAttributeElement, and.getPrefix(), and.getLocalname())
          .cloneNode(true);
      payloadAttributeElement.setAttributeNode(payloadAttribute);
    }

    // 4) Set values according to possibility index
    // /////////////////////////////////////////////
    String attributelement = payloadAttributeElement.getNodeName();
    String attributename = payloadAttribute.getNodeName();
    switch (index)
    {
    // 0) Payload gets a new attribute value
      case 0:
// Attr signedAttribute = getAttributeByQualifiedName(signedAttributeElement, and.getPrefix(), and.getLocalname());
        if (signedAttribute.getValue().equals(payloadAttribute.getValue())) // if they already differ (user set id),
// nothing will be changed.
          payloadAttribute.setNodeValue("attack" + and.getValue()); // TODO: Use random Value, maybe check for some
// type,
// e.g. Integer

        WeaknessLog
            .append(String
                .format("Payload element %s gets a new attribute value %s='%s'", attributelement, attributename, payloadAttribute
                    .getValue()));
        break;
      // 1) Remove attribute from payload
      case 1:
        payloadAttributeElement.removeAttributeNode(payloadAttribute);
        WeaknessLog.append(String.format("Removed attribute from from payload element %s", attributelement));
        break;
      // 2) Payload and Signed Element have the same attribute value
      case 2:
        String value = and.getValue();
        payloadAttribute.setNodeValue(value);
        WeaknessLog.append(String
            .format("Both %s elements have the same attribute value %s='%s'", attributelement, attributename, value));
        break;

      default:

        String error = "Index out of range: '" + index + "'";
        log.warn(error);
        throw new InvalidWeaknessException(error);
    }

  }

  public static Attr getAttributeByQualifiedName(Element element,
                                                 String prefix,
                                                 String localname)
  {
    if (prefix == null || prefix.isEmpty())
      return element.getAttributeNode(localname);

    NamedNodeMap attributes = element.getAttributes();
    for (int i = 0; i < attributes.getLength(); ++i)
    {
      Attr attribute = (Attr) attributes.item(i);
      if (attribute.getLocalName().equals(localname) && attribute.getPrefix() != null && attribute.getPrefix()
          .equals(prefix))
      {
        return attribute;
      }
    }

    return null;
  }

  public Step getStep()
  {
    return step;
  }

}
