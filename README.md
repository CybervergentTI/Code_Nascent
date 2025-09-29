=> This cell is the first step to access your Google Drive files from your Colab notebook, which is necessary for the subsequent code to read the PDF reports from your "Weekly" folder.


from google.colab import drive
drive.mount('/content/drive')


#This cell code defines the target folder path, lists the files in the folder, and prints the result present in the specified folder.


=> import os

drive_folder_path = '/content/drive/MyDrive/Weekly'

try:
    files = os.listdir(drive_folder_path)
    print(f"Files found in '{drive_folder_path}':")
    for file in files:
        print(file)
except FileNotFoundError:
    print(f"Error: Folder not found at {drive_folder_path}")
except Exception as e:
    print(f"Error listing files: {str(e)}")

    

=> Install PDF files reader


!pip install PyPDF2
!pip install PyMuPDF
!pip install tabula
