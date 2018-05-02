;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*- 

;;; an example network from the Iroom
;;; dwarfs: dopey, sleepy, grumpy, sneezy 

(in-package :aplan)

(defun setup-jbi-site (&key clear-first)
  (when clear-first (clear))
;;; Two network sites reflecting the physical split
;;; one for maf-caf
;;; one for core
;;; We'll assume each site is a Class C
;;; In effect there are three subnets:
;;; the one connecting guys in maf-caf
;;; the one connecting guys in core
;;; the public (shared-media) network connecting the switches and routers

;;; MAF subnet is 128.54.1.xxx
;;; CAF subnet is 128.54.2.xxx
;;; Switches are at 128.54.sub.2 (for sub in {1,2})
;;; typical machines are at 128.54.sub.100

  (defsite jbi-core-site "128.54.1.0" "255.255.255.0")
  (defsite maf-caf-site  "128.54.2.0"  "255.255.255.0")

  (defsubnet backbone switched-subnet "128.55.0.0" "255.255.0.0")
  (defsubnet jbi-core-subnet switched-subnet "128.54.1.0" "255.255.255.0")
  (defsubnet maf-caf-subnet switched-subnet "128.54.2.0" "255.255.255.0")


  (make-object 'authorization-pool :name 'router-pool)
  (make-object 'authorization-pool :name 'server-pool)
  (make-object 'authorization-pool :name 'user-pool)

;;; user pool

  (defcapability super-user user-pool)

  (defcapability user-write user-pool
    :greater (super-user))

  (defcapability user-read user-pool
    :greater (user-write))

  (defuser administrator
      :capabilities (super-user)
      :authorization-pools (user-pool)) 

  (defcomputer typical-maf-caf-computer typical-computer "128.54.2.100"
	       :superuser administrator
	       :authorization-pool user-pool)

  (defcomputer typical-core-computer typical-computer "128.54.1.100"
	       :superuser administrator
	       :authorization-pool user-pool)

  (defuser typical-user 
      :user-type typical-user
      :capabilities (user-write)
      :authorization-pools (user-pool)
      :machines (typical-core-computer typical-maf-caf-computer))

  (defresource user-machine-scheduler-policy scheduler-policy-file
	       :capability-requirements ((write super-user)
					 (read user-read))
	       :machines (typical-maf-caf-computer))

  (defresource user-password-file password-file
	       :capability-requirements ((write super-user)
					 (read user-read))
	       :machines (typical-maf-caf-computer))
  
  (defresource typical-maf-java-file typical-java-file
	       :capability-requirements ((write user-write)
					 (read user-read))
	       :machines (typical-maf-caf-computer)
	       )
  
  (defresource typical-maf-class-file typical-class-file
	       :capability-requirements ((write user-write)
					 (read user-read))
	       :machines (typical-maf-caf-computer)
	       )
  
  (tell `[ltms:value-of (typical-maf-class-file source-file) ,(follow-path '(typical-maf-java-file))])

  (defresource maf-editor program
	       :machines (typical-maf-caf-computer)
	       )
  
  (tell `[ltms:value-of (maf-editor load-files) ,(follow-path '(typical-maf-class-file))])

  (defresource user-typical-file typical-file
	       :capability-requirements ((write user-write) 
					 (read user-read))
	       :machines (typical-maf-caf-computer))

  (defresource typical-graphics-file typical-graphics-image-file
	       :capability-requirements ((write super-user)
					 (read user-read))
	       :machines (typical-maf-caf-computer))

  (defresource typical-maf-plan typical-file
	       :capability-requirements ((write user-write)
					 (read user-read))
	       :machines (typical-maf-caf-computer))
	     
  (defresource maf-caf-oadb database
	       :capability-requirements ((write super-user)
					 (read user-read))
	       :machines (typical-maf-caf-computer))

  (defresource core-typical-file typical-file
	       :capability-requirements ((write user-write) 
					 (read user-read))
	       :machines (typical-core-computer))

  (defresource core-oadb database
	       :capability-requirements ((write super-user)
					 (read user-read))
	       :machines (typical-core-computer))
  
  

  ;; servers pool

  (defcapability server-super-user server-pool)

  (defcapability server-user-write server-pool
    :greater (server-super-user))

  (defcapability server-user-read server-pool
    :greater (server-user-write)) 

  (defuser server-administrator
      :capabilities (server-super-user)
      :authorization-pools (server-pool)) 

  (defcomputer life solaris-computer "128.54.1.1"
	       :authorization-pool server-pool
	       :superuser server-administrator)

;;; router pool
  (defcapability router-super-user router-pool)

  (defcapability router-user-write router-pool
    :greater (router-super-user))

  (defcapability router-user-read router-pool
    :greater (router-user-write)) 

  (defuser router-administrator
      :capabilities (router-super-user)
      :authorization-pools (router-pool))


;;; network topology
;;; two switched subnets: one for maf-caf one for core 
;;; Switches are at 2 in each subnet
;;; There is a router that each of these connects to
;;; Router is at 10 in each subnet
;;; I don't know if that's actually possible

  (defswitch maf-caf switch "128.54.2.2" 
	     :authorization-pool router-pool 
	     :superuser router-administrator)

  (defswitch core switch "128.54.1.2" 
	     :authorization-pool router-pool 
	     :superuser router-administrator)

  (defrouter jbi-router ("128.54.1.10" "128.54.2.10")
    :authorization-pool router-pool 
    :superuser router-administrator)

  (defcomputer maf1 windows-2000-computer "128.54.2.20" 
	       :superuser administrator
	       :authorization-pool user-pool)

  (defcomputer jbi-core linux-computer "128.54.1.20" 
	       :superuser server-administrator
	       :authorization-pool server-pool)

  (defcomputer jbi-maf-backup linux-computer "128.54.1.21"   
	       :superuser administrator
	       :authorization-pool user-pool)

  (defcomputer jbi-clients linux-computer "128.54.1.22"   
	       :superuser administrator
	       :authorization-pool user-pool)

  (defresource router-password-file password-file
	       :capability-requirements ((write router-super-user)
					 (read router-user-read))
	       :machines (maf-caf core jbi-router ))

  (define-object-type maf-process
      :included-object-types (user-process))

  (defrule maf-runs-at-user-level (:forward)
    if [ltms:object-type-of ?process maf-process]
    then `[runs-with-permissions-of ?process ,(follow-path '(typical-user))])


;;; site accepts telnets and remote-screen only from within but ssh from anywhere
  (tell-policy jbi-router remote-screen 
	       :negative-location-mask "255.255.0.0" 
	       :negative-location-address "128.54.0.0")
  (tell-policy jbi-router telnet :negative-location-mask "255.255.0.0" :negative-location-address "128.54.0.0")
  (tell-policy jbi-router ssh :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")

;;; subnet accepts remote-screen and telnets only from within the subnet
;;; subnet accepts ssh from anywhere
  (tell-policy core remote-screen :negative-location-mask "255.255.0.0" :negative-location-address "128.54.0.0")
  (tell-policy core telnet :negative-location-mask "255.255.0.0" :negative-location-address "128.54.0.0")
  (tell-policy core ssh :positive-location-mask "255.255.0.0" :positive-location-address "128.54.0.0")

  ;; subnet accepts remote-screen and telnets only from within the subnet
;;; subnet accepts ssh from anywhere
  (tell-policy maf-caf remote-screen
	       :negative-location-mask "255.255.0.0" 
	       :negative-location-address "128.54.0.0")
  (tell-policy maf-caf telnet :negative-location-mask "255.255.0.0" :negative-location-address "128.54.0.0")
  (tell-policy maf-caf ssh :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")

  (tell-policy * email :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")

  ;; (instantiate-a-process 'iis-web-server-process '(maf1) :role-name 'web-server-process)
  (instantiate-a-process 'typical-user-process '(typical-maf-caf-computer) :role-name 'maf-client)
  (instantiate-a-process 'maf-process '(typical-maf-caf-computer) :role-name 'typical-maf-editor-process)
  (tell `[ltms:value-of (typical-maf-editor-process program) ,(follow-path '(maf-editor))])
  (tell `[output-of ,(follow-path '(typical-maf-editor-process)) ,(follow-path '(typical-maf-plan))])
  (tell `[input-of ,(follow-path '(typical-maf-editor-process)) ,(follow-path '(typical-graphics-file))])

  (create-attacker 'test-attack :negative-mask-address "128.54.0.0" :negative-mask-mask "255.255.0.0")
  (defuser insider-attacker
      :user-type attacker
      :authorization-pools (user-pool server-pool)
      :capabilities (super-user server-super-user)
      :positive-address "128.54.0.0" :positive-mask "255.255.0.0"
      )
  )