package wsattacker.plugin.optionsTester.option;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOptionComplex;

/**
 * Simple multifile select option.
 * Used to selecte multiple XML Schema files.
 */
public class OptionSchemaFiles extends AbstractOptionComplex
{

  private static final long serialVersionUID = 1L;
  List<File> files = new ArrayList<File>();

  public OptionSchemaFiles()
  {
    super("Used\nSchema\nfiles", "Set the Schema Files.\nSoap11, Soap12, WSA, WSSE, WSU, DS and XPathFilter2\nare included by default.");
  }

  public void setFiles(List<File> files)
  {
    this.files = files;
  }

  public void setFiles(File[] files)
  {
    this.files = new ArrayList<File>(files.length);
    for (File f : files)
    {
      this.files.add(f);
      Logger.getLogger(getClass()).info("Using Schema: " + f.toString());
    }
  }

  public List<File> getFiles()
  {
    return files;
  }

  @Override
  public AbstractOptionGUI getComplexGUI(ControllerInterface controller,
                                         AbstractPlugin plugin)
  {
    return new OptionSchemaFilesGUI(controller, plugin, this);
  }

  public boolean isValid(File file)
  {
    return file == null || file.exists() && file.isFile();
  }

  public boolean isValid(File[] files)
  {
    for (File f : files)
      if (!isValid(f))
        return false;
    return true;
  }

  @Override
  public boolean isValid(String value)
  {
    String[] values = value.split(", ");
    for (String name : values)
      try
      {
        new File(name);
      }
      catch (Exception e)
      {
        return false;
      }
    return true;
  }

  @Override
  public boolean parseValue(String value)
  {
    String[] values = value.split(", ");
    files = new ArrayList<File>();
    for (String name : values)
      try
      {
        files.add(new File(name));
      }
      catch (Exception e)
      {
        files.clear();
        return false;
      }
    return true;
  }

  @Override
  public String getValueAsString()
  {
    StringBuffer buf = new StringBuffer();
    for (File f : files)
      buf.append(f.toString()).append(", ");
    if (buf.length() > 2)
      buf.delete(buf.length() - 2, buf.length());
    return buf.toString();
  }

  public String getShortValueAsString()
  {
    StringBuffer buf = new StringBuffer();
    for (File f : files)
      buf.append(f.getName()).append(", ");
    if (buf.length() > 2)
      buf.delete(buf.length() - 2, buf.length());
    return buf.toString();
  }

}
