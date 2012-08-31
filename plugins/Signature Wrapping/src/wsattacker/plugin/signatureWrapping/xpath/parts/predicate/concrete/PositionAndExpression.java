package wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete;

import java.util.regex.Pattern;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidTypeException;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.AndExpression;

public class PositionAndExpression extends AndExpression
{
  
  private String function;
  private int position;
  private String positonFunction;

  public PositionAndExpression(String expression) throws InvalidTypeException
  {
    super(expression);
    function = "";
    position = -1; // invalid position
    positonFunction = "";
    
    final String POSITION = "position()=";
    final String LAST = "last()";
    
    if (expression.startsWith(POSITION)) {
      function = POSITION.substring(0, POSITION.length()-1);
      positonFunction = expression.substring(POSITION.length()).trim();
      expression = positonFunction;
    }
      
    if (isPosition(expression))
      try
      {
        position = Integer.parseInt(expression);
      }
      catch (NumberFormatException e)
      {
        throw new InvalidTypeException();
      }
    else 
      if (expression.startsWith(LAST)) {
        positonFunction = expression;
      }
    
    if (position < 1 && positonFunction.isEmpty())
      throw new InvalidTypeException();
  }
  
  public boolean isPosition(String s) {
    final Pattern positionPattern = Pattern.compile("^[1-9][0-9]*$");
    return positionPattern.matcher(s).find();
  }

  public String getFunction()
  {
    return function;
  }

  public int getPosition()
  {
    return position;
  }

  public String getPositonFunction()
  {
    return positonFunction;
  }
  
  public boolean isSimpleIndex() {
    return position>0;
  }

}
