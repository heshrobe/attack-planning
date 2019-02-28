;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*- 

;;; an example network from the Iroom
;;; dwarfs: dopey, sleepy, grumpy, sneezy 

(in-package :aplan)

(defsite ai-lab "128.52.0.0" "255.255.0.0")

(make-object 'authorization-pool :name 'router-pool)
(make-object 'authorization-pool :name 'server-pool)
(make-object 'authorization-pool :name 'dwarf-pool)
(make-object 'authorization-pool :name 'lispms)

(defcapability dwarf-super-user dwarf-pool)

(defcapability dwarf-user-write dwarf-pool
  :greater (dwarf-super-user))

(defcapability dwarf-user-read dwarf-pool
  :greater (dwarf-user-write)) 

(defuser dwarfs-administrator
  :capabilities (dwarf-super-user)
  :authorization-pools (dwarf-pool)) 

(defcomputer typical-dwarf computer "128.52.54.0"
  :superuser dwarfs-administrator
  :authorization-pool dwarf-pool)

(defuser dwarf-user 
  :user-type typical-user
  :capabilities (dwarf-user-write)
  :authorization-pools (dwarf-pool)
  :machines (typical-dwarf))

(defcomputer dopey windows-2000-computer "128.52.54.145" 
  :superuser dwarfs-administrator
  :authorization-pool dwarf-pool)

(defcomputer sleepy windows-2000-computer "128.52.54.146"   
  :superuser dwarfs-administrator
  :authorization-pool dwarf-pool)

(defcomputer sneezy linux-computer "128.52.54.147" 
  :superuser dwarfs-administrator
  :authorization-pool dwarf-pool)

(defcomputer grumpy linux-computer "128.52.54.148" 
  :superuser dwarfs-administrator
  :authorization-pool dwarf-pool) 

(defresource dwarfs-scheduler-policy scheduler-policy-file
  :capability-requirements ((write dwarf-super-user)
                            (read dwarf-user-read))
  :machines (grumpy sneezy sleepy dopey typical-dwarf))

(defresource dwarfs-password-file password-file
  :capability-requirements ((write dwarf-super-user)
                            (read dwarf-user-read))
  :machines (grumpy sneezy sleepy dopey typical-dwarf))

(defresource dwarf-typical-file file
  :capability-requirements ((write dwarf-user-write) 
                            (read dwarf-user-read))
  :machines (grumpy sneezy sleepy dopey typical-dwarf)) 

;; lispms

(defcapability lispm-super-user lispms)

(defcapability lispm-normal lispms
  :greater (lispm-super-user)) 

(defuser lispm-administrator
  :capabilities (lispm-super-user)
  :authorization-pools (lispms))

(defcomputer truman lispm-computer "128.52.39.145"
  :superuser lispm-administrator
  :authorization-pool lispms)

(defcomputer wilson lispm-computer "128.52.33.12"
  :superuser lispm-administrator
  :authorization-pool lispms )

(defcomputer sakharov solaris-computer "128.52.39.45"
  :superuser lispm-administrator
  :authorization-pool lispms)

;; servers subnet

(defcapability server-super-user server-pool)

(defcapability server-user-write server-pool
  :greater (server-super-user))

(defcapability server-user-read server-pool
  :greater (server-user-write)) 

(defuser server-administrator
  :capabilities (server-super-user)
  :authorization-pools (server-pool)) 

(defcomputer life solaris-computer "128.52.52.9"
  :authorization-pool server-pool
  :superuser server-administrator)

;;; network topology
;;; Each subnet has a switch at the 10 address
;;; each of those guys in turn connects to the router
;;; are the switches on 1 or 2 subnets
;;; how do the switches and net-chex relate?
;;; does net-chex then connect to radole?

;;; 8th floor subnet-1

(defcapability router-super-user router-pool)

(defcapability router-user-write router-pool
  :greater (router-super-user))

(defcapability router-user-read router-pool
  :greater (router-user-write)) 

(defuser router-administrator
  :capabilities (router-super-user)
  :authorization-pools (router-pool))

(defswitch switch-9-5-2 switch "128.52.52.2" :authorization-pool router-pool :superuser router-administrator)

(defswitch switch-8-54-2 switch "128.52.54.2" :authorization-pool router-pool :superuser router-administrator)

(defswitch switch-8-39-2 switch "128.52.39.2" :authorization-pool router-pool :superuser router-administrator)

(defswitch switch-7-33-2 switch "128.52.33.2" :authorization-pool router-pool :superuser router-administrator) 

(defrouter net-chex ("128.52.54.10" "128.52.39.10" "128.52.33.10" "128.52.52.10")
  :authorization-pool router-pool :superuser router-administrator)

(defresource router-password-file password-file
	:capability-requirements ((write router-super-user)
                                  (read router-user-read))
	:machines (switch-9-5-2 switch-8-54-2 switch-8-39-2 switch-7-33-2 net-chex))

(defsubnet backbone switched-subnet "128.52.52.0" "255.255.255.0")

(defsubnet 8th-floor-2 switched-subnet "128.52.54.0" "255.255.255.0")

(defsubnet 8th-floor-1 switched-subnet "128.52.39.0" "255.255.255.0")

(defsubnet 7th-floor-1 switched-subnet "128.52.33.0" "255.255.255.0")


;; site accepts telnets only from within
(tell-policy net-chex telnet :negative-location-mask "255.255.0.0" :negative-location-address "128.52.0.0")
(tell-policy net-chex ssh :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")

;; subnet accepts telnets only from within the subnet
(tell-policy switch-8-39-2 telnet :negative-location-mask "255.255.255.0" :negative-location-address "128.52.39.0")
(tell-policy switch-8-39-2 ssh :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")

;; subnet accepts telnets only from within the subnet
(tell-policy switch-8-54-2 telnet :negative-location-mask "255.255.255.0" :negative-location-address "128.52.54.0")
(tell-policy switch-8-54-2 ssh :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")
(tell-policy * email :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")


(instantiate-a-process 'iis-web-server-process '(dopey))
(instantiate-a-process 'cl-http-server-process '(sakharov))
(instantiate-a-process 'typical-user-process '(dopey) :role-name 'typical-dopey-process)
(instantiate-a-process 'typical-user-process '(typical-dwarf) :role-name 'typical-dwarf-process)


(create-attacker 'typical-attacker :negative-mask-address "128.52.0.0" :negative-mask-mask "255.255.0.0") 


#|

(tell [is-a-mapping authentication-file user access-right])

(tell [residence authentication-file file-system])

(tell [residence authentication-file main-memory])

lots more ideas:

If a machine is on a shared-media subnet and you control its network stack
   then you can see all the network traffic of any other machine on that subnet
If you can control the switch on a switch-media subnet then you can see all the traffic
   of any other machine on that subnet
If you can see the traffic to a machine and that machine uses an unsecured protocol
  and the protocol transmits passwords, then you can sniff passwords
telnet is an unsecured protocol that transmits passwords
email is an unsecured protocol that transmits passwords
there should be an object type for protocols

the should probably be objects for "typical machines" and "typical users"

one can guess root passwords for any machine

|#