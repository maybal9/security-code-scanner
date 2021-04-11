using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System;
using Newtonsoft.Json;

public class Scanner{

    Regex Cross_Site_Scripting_Regex; 
    List<string> prohibited_combinations_strings;
    Regex SQL_injection_indication; 

    List<Anomaly> Anomaly_Log;

    void PopulateProhibitedCombinations(){
        this.prohibited_combinations_strings = new List<string>();
        this.prohibited_combinations_strings.Add("Checkmarx");
        this.prohibited_combinations_strings.Add("Hellman & Friedman");
        this.prohibited_combinations_strings.Add("$1.15b");
    }

    void BuildSQLRegex(){    
        string qoutes_pat = "\\\"";
        string select_pat = "\\b(SELECT|select|Select)\\b";
        string where_pat = "\\b(WHERE|where|Where)\\b";
        string special_sym = "(\\%s)\\b";
        this.SQL_injection_indication = new Regex("^" + qoutes_pat
            + ".*"+ select_pat +".*"+ where_pat +".*"+ special_sym +".*"
            + qoutes_pat + "$");
    }

    void BuildAlertRegex(){
        string alert_pat = "(Alert\\(\\))";
        this.Cross_Site_Scripting_Regex = new Regex("^" + alert_pat + "$");
    }

    public Scanner(){
        BuildAlertRegex();
        PopulateProhibitedCombinations();
        BuildSQLRegex();
        this.Anomaly_Log = new List<Anomaly>();
    }

    bool SearchCrossSiteScripting(string line){
        bool alert_found = this.Cross_Site_Scripting_Regex.Match(line).Success;
        return alert_found; 
    }
    bool SearchSensitiveDataExposure(string line){
        bool found = this.prohibited_combinations_strings.All(line.Contains);
        return found;
    }

    bool SearchSQLInjection(string line){
        bool sql_found = this.SQL_injection_indication.Match(line).Success;
        return sql_found;
    }

    void LogAnomaly(string anomaly_type, string file_name, int line_num){
        Anomaly a = new Anomaly(anomaly_type, file_name, line_num);
        Anomaly_Log.Add(a);
    }

    void WriteAnomalyReport(string output_format = "text"){
        if (output_format == "json"){
            var json = JsonConvert.SerializeObject(this.Anomaly_Log, Formatting.Indented);
            Console.Write(json);
            return;
        }
        foreach (Anomaly a in this.Anomaly_Log){
            Console.WriteLine(a.PrintAnomaly());
        }
    }

    void ScanFile(string file_path){
        int counter = 0;
        string line;
        string filename = file_path.Split('\\').Last();
        string file_ext = filename.Split('.').Last();
        bool file_suspect_for_alert = file_ext == "json" || file_ext == "html";
        try{
            StreamReader f = new StreamReader(file_path);
            while ((line = f.ReadLine()) != null){
                if(SearchSensitiveDataExposure(line)){
                    LogAnomaly("Sensitive Data Exposure", filename, counter);
                }
                if (/*file_suspect_for_alert &&*/ SearchCrossSiteScripting(line)){
                    LogAnomaly("Cross Site Scripting", filename, counter);
                }
                if (SearchSQLInjection(line)){
                    LogAnomaly("SQL Injection", filename, counter);
                }
                counter++;
            }
        } 
        catch (Exception){
            //log err: couldn't open file
        }
    }
    public void Scan(string input_path, string output_format){
        this.Anomaly_Log.Clear();
        string[] file_paths = Directory.GetFiles(input_path);
        foreach (var file in file_paths){
            ScanFile(file);
        }
        WriteAnomalyReport(output_format);
    }
}