from django.db import models

# Create your models here.
class VIS_UserLogin(models.Model):
	UserNameLogin = models.CharField(max_length=50)
	PasswordLogin = models.TextField()
	NamaVendor = models.TextField()
	KodeVendor = models.CharField(max_length=50)
	HasChangePassword = models.IntegerField()
	Status = models.CharField(max_length=50)
	Priv = models.IntegerField()

	class Meta:
		managed = False
		db_table = 'VIS_UserLogin2'

	def __str__(self):
		return f"{self.UserNameLogin}|{self.NamaVendor}|{self.KodeVendor}|{self.HasChangePassword}|{self.Status}"
	
class VisUserlogin1(models.Model):
	#id = models.AutoField(db_column='ID')  # Field name made lowercase.
	usernamelogin = models.CharField(db_column='UserNameLogin', max_length=50)  # Field name made lowercase.
	passwordlogin = models.TextField(db_column='PasswordLogin')  # Field name made lowercase. This field type is a guess.
	namavendor = models.TextField(db_column='NamaVendor')  # Field name made lowercase. This field type is a guess.
	kodevendor = models.CharField(db_column='KodeVendor', max_length=50)  # Field name made lowercase.
	haschangepassword = models.IntegerField(db_column='HasChangePassword')  # Field name made lowercase.
	status = models.CharField(db_column='Status', max_length=50)  # Field name made lowercase.

	class Meta:
		managed = False
		db_table = 'VIS_UserLogin'

	def __str__(self):
		return f"{self.usernamelogin}|{self.namavendor}|{self.kodevendor}|{self.haschangepassword}|{self.status}"

class VisSessions(models.Model):
	session_id = models.CharField(max_length=200, blank=True, null=False)
	username = models.CharField(max_length=50, blank=True, null=True)
	ip_address = models.CharField(max_length=50, blank=True, null=True)
	user_agent = models.CharField(max_length=150, blank=True, null=True)
	last_activity = models.DateTimeField(blank=True, null=True)
	is_login = models.IntegerField(blank=True, null=True)

	class Meta:
		managed = False
		db_table = 'vis_sessions2'

	def __str__(self):
		return f"{self.session_id} [{self.ip_address}]|[{self.username}]|{self.last_activity} - {self.user_agent}"

#class VisLogs(models.Model):
	#time = models.DateTimeField()
	#path = models.CharField(max_length=50)
	#session_id = models.CharField(max_length=200)
	#username = models.CharField(max_length=50)
	#ip_address = models.CharField(max_length=50)
	#user_agent = models.CharField(max_length=150)
	#module = models.CharField(max_length=100)
	#message = models.Charfield(max_length=100)

	#class Meta:
		#managed = False
		#db_table = 'VIS_logs'

class VisLogs(models.Model):
	#id = models.BigAutoField()
	time = models.DateTimeField()
	path = models.CharField(max_length=50, blank=True, null=True)
	session_id = models.CharField(max_length=200, blank=True, null=True)
	username = models.CharField(max_length=50, blank=True, null=True)
	ip_address = models.CharField(max_length=50, blank=True, null=True)
	user_agent = models.CharField(max_length=255, blank=True, null=True)
	module = models.CharField(max_length=100, blank=True, null=True)
	message = models.TextField(blank=True, null=True)  # This field type is a guess.

	class Meta:
		managed = False
		db_table = 'VIS_logs'
		
	def __str__(self):
		return f"{self.time} - {self.path} - {self.session_id} [{self.ip_address}]|[{self.username}]|{self.user_agent}"
	
class VIS_UserLogin2_Priv(models.Model):
	#id = models.BigAutoField()
	code = models.IntegerField(blank=False, null=False)
	name = models.CharField(max_length = 200, blank=False, null=False)

	class Meta:
		managed = False
		db_table = 'VIS_UserLogin2_Priv'
		
	def __str__(self):
		return f"{self.code} - {self.name}"

class ItemmasterdataVis(models.Model):
	itemcode = models.CharField(db_column='ItemCode', max_length=50)  # Field name made lowercase.
	preferred_vendor = models.CharField(db_column='Preferred_Vendor', max_length=15, blank=True, null=True)  # Field name made lowercase.
	length = models.DecimalField(db_column='Length', max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	width = models.DecimalField(db_column='Width', max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	height = models.DecimalField(db_column='Height', max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	volume = models.DecimalField(db_column='Volume', max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	weight = models.DecimalField(db_column='Weight', max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	dimension = models.DecimalField(db_column='Dimension', max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	attachment = models.BinaryField(db_column='Attachment', blank=True, null=True)  # Field name made lowercase.

	class Meta:
		managed = False
		db_table = 'ItemMasterData_VIS'
		
	def __str__(self):
		return self.itemcode

class ItemMasterData_VIS(models.Model):
	ItemCode = models.CharField(max_length=50)  # Field name made lowercase.
	Preferred_Vendor = models.CharField(max_length=15, blank=True, null=True)  # Field name made lowercase.
	Length = models.DecimalField(max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	Width = models.DecimalField(max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	Height = models.DecimalField(max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	Volume = models.DecimalField(max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	Weight = models.DecimalField(max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	Dimension = models.DecimalField(max_digits=19, decimal_places=0, blank=True, null=True)  # Field name made lowercase.
	Attachment = models.BinaryField(blank=True, null=True)  # Field name made lowercase.

	class Meta:
		managed = False
		db_table = 'ItemMasterData_VIS'
		
	def __str__(self):
		return self.ItemCode