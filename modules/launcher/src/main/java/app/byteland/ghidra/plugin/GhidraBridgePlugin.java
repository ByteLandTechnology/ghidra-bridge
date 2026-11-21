package app.byteland.ghidra.plugin;

import app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.BridgeServices;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.bean.opteditor.OptionsVetoException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;

/**
 * CodeBrowser plugin that runs the Ghidra Bridge listener in the background and tracks active tabs.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Ghidra Bridge MCP and WebSocket service",
    description =
        "Exposes the active CodeBrowser program over a background MCP HTTP or WebSocket bridge"
            + " and connects open sessions to ghidra-mcp.",
    eventsConsumed = {
      ProgramActivatedPluginEvent.class,
      ProgramOpenedPluginEvent.class,
      ProgramClosedPluginEvent.class
    })
public class GhidraBridgePlugin extends ProgramPlugin implements OptionsChangeListener {
  public static final String STATUS_COMPONENT_NAME = "ghidra-bridge-status";
  private static final String MENU_GROUP = "Ghidra Bridge";

  private final AtomicReference<Program> activeProgramRef = new AtomicReference<>();
  private final Set<Program> openPrograms =
      Collections.synchronizedSet(Collections.newSetFromMap(new IdentityHashMap<>()));
  private final GhidraSession session;
  private final BridgeServices services;
  private final JLabel statusLabel;
  private final BridgeBackgroundRuntime runtime;
  private final ExecutorService cleanupExecutor;
  private ToolOptions toolOptions;

  public GhidraBridgePlugin(PluginTool tool) {
    super(tool);
    this.session = new GhidraSession(activeProgramRef::get);
    this.services = GhidraServiceFactory.create(session, "ghidra-bridge");
    this.statusLabel = new JLabel("Bridge: idle (no program)");
    this.statusLabel.setName(STATUS_COMPONENT_NAME);
    this.statusLabel.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 6));
    this.statusLabel.setToolTipText("Ghidra Bridge status and active port");
    this.cleanupExecutor =
        Executors.newSingleThreadExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "ghidra-bridge-program-cleanup");
              thread.setDaemon(true);
              return thread;
            });
    this.runtime =
        new BridgeBackgroundRuntime(
            services, activeProgramRef::get, DaemonAttachDiscovery::discover, this::updateStatusLabel);
  }

  @Override
  protected void init() {
    super.init();
    toolOptions = tool.getOptions(PluginSettings.OPTIONS_CATEGORY);
    PluginSettings.registerOptions(toolOptions);
    toolOptions.addOptionsChangeListener(this);
    tool.addStatusComponent(statusLabel, true, false);
    registerActions();
    runtime.applySettings(PluginSettings.fromOptions(toolOptions), hasAnyOpenProgram());
  }

  @Override
  protected void programOpened(Program program) {
    if (program != null) {
      openPrograms.add(program);
    }
  }

  @Override
  protected void programActivated(Program program) {
    if (program != null) {
      openPrograms.add(program);
    }
    activeProgramRef.set(program);
    runtime.onProgramActivated(program);
  }

  @Override
  protected void programDeactivated(Program program) {
    if (program != null) {
      activeProgramRef.compareAndSet(program, null);
    }
    runtime.onProgramDeactivated();
  }

  @Override
  protected void programClosed(Program program) {
    if (program != null) {
      openPrograms.remove(program);
      activeProgramRef.compareAndSet(program, null);
      cleanupExecutor.execute(() -> session.notifyProgramClosed(program));
    }
    if (!hasAnyOpenProgram()) {
      runtime.onAllProgramsClosed();
    } else {
      runtime.onProgramDeactivated();
    }
  }

  @Override
  public void optionsChanged(
      ToolOptions options, String optionName, Object oldValue, Object newValue)
      throws OptionsVetoException {
    PluginSettings.validateOptionChange(optionName, newValue);
    runtime.applySettings(PluginSettings.fromOptions(options), hasAnyOpenProgram());
  }

  @Override
  protected void dispose() {
    activeProgramRef.set(null);
    openPrograms.clear();
    if (toolOptions != null) {
      toolOptions.removeOptionsChangeListener(this);
    }
    tool.removeStatusComponent(statusLabel);
    cleanupExecutor.shutdownNow();
    Thread shutdownThread =
        new Thread(
            () -> {
              runtime.close();
              services.close();
            },
            "ghidra-bridge-plugin-dispose");
    shutdownThread.setDaemon(true);
    shutdownThread.start();
    super.dispose();
  }

  public String statusText() {
    return statusLabel.getText();
  }

  public BridgeBackgroundRuntime runtime() {
    return runtime;
  }

  private void registerActions() {
    DockingAction startAction =
        new DockingAction("Start or Restart Bridge", getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            runtime.startOrRestartManual();
          }
        };
    startAction.setMenuBarData(
        new MenuData(
            new String[] {"Tools", MENU_GROUP, "Start or Restart Bridge"}, null, MENU_GROUP));
    startAction.setDescription("Start or restart the local Ghidra Bridge listener.");
    startAction.markHelpUnnecessary();
    tool.addAction(startAction);

    DockingAction stopAction =
        new DockingAction("Stop Bridge", getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            runtime.stopManual();
          }
        };
    stopAction.setMenuBarData(
        new MenuData(new String[] {"Tools", MENU_GROUP, "Stop Bridge"}, null, MENU_GROUP));
    stopAction.setDescription("Stop the local Ghidra Bridge listener and daemon connection.");
    stopAction.markHelpUnnecessary();
    tool.addAction(stopAction);

    DockingAction attachAction =
        new DockingAction("Attach to ghidra-mcp", getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            runtime.attachNow();
          }
        };
    attachAction.setMenuBarData(
        new MenuData(
            new String[] {"Tools", MENU_GROUP, "Attach to ghidra-mcp"}, null, MENU_GROUP));
    attachAction.setDescription("Connect the active program to a local ghidra-mcp daemon.");
    attachAction.markHelpUnnecessary();
    tool.addAction(attachAction);
  }

  private boolean hasAnyOpenProgram() {
    if (!openPrograms.isEmpty()) {
      return true;
    }
    ProgramManager manager = tool.getService(ProgramManager.class);
    return manager != null && manager.getAllOpenPrograms().length > 0;
  }

  private void updateStatusLabel(String text) {
    Runnable update =
        () -> {
          statusLabel.setText(text);
          String endpoint = runtime.localEndpoint();
          statusLabel.setToolTipText(
              endpoint == null ? text : text + " (" + endpoint + ")");
        };
    if (SwingUtilities.isEventDispatchThread()) {
      update.run();
    } else {
      SwingUtilities.invokeLater(update);
    }
  }
}
