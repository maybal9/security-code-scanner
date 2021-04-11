using System;
using Newtonsoft.Json;

public class Anomaly{
    [JsonProperty]
    string Anomaly_Type;
    [JsonProperty]
    string File;
    [JsonProperty]
    int Line_Number;
    
    [JsonConstructor]
    public Anomaly(string anomaly_type, string file, int line_num){
        this.Anomaly_Type = anomaly_type;
        this.File = file;
        this.Line_Number = line_num;
    }

    public string PrintAnomaly(){
        return String.Format("[{0}] in file \"{1}\" on line {2}", this.Anomaly_Type, this.File, this.Line_Number);
    }
}