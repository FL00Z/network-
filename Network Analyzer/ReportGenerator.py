import csv
import datetime
import json
import os


class Report_Generator:
    def __init__(self):
        self.default_name_csv  = 'ReportCSV'
        self.default_name_txt  = 'ReportText'
        self.default_name_json = 'ReportJSON'


    def _get_unique_filename(self, filename):
        """Generates a unique filename by appending numbers if the file already exists."""
        base, ext = os.path.splitext(filename)
        counter = 1
        new_filename = filename
        while os.path.exists(new_filename):
            new_filename = f"{base}({counter}){ext}"
            counter += 1
        return new_filename
    
    
    
