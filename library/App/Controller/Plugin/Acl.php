<?php
/**
 * Zend ACL (A)ccess (C)ontrol (L)ist Implementation
 * 
 * @see 		http://framework.zend.com/manual/en/zend.acl.html
 * @author		Tom Shaw [tom at tomshaw dot info]
 * @copyright	(C) Tom Shaw 2012. All rights reserved.
 * @license     MIT Licensed
 */
class App_Controller_Plugin_Acl extends Zend_Controller_Plugin_Abstract implements IteratorAggregate, Countable
{
    /**
     * A static array of system roles. The entire system reads from this array. A public static 
     * helper method is used to access system roles outside of the scope of this object. Persistence 
     * wise user identities are calculated based on the position in the stack, ie zero would be Anonymous
     * and three is an Administrator.
     * 
     * App_Plugin_Auth_Acl::getRoles();
     *
     * @var static array
     */
    private static $_roles = array(
        'anonymous' => 'Anonymous', // 0
        'member' => 'Member', // 1
        'moderator' => 'Moderator', // 2 
        'administrator' => 'Administrator' // 3
    );
    
    /**
     * A container for the current user role.
     *
     * @var string
     */
    private $_role = null;
    
    /**
     * A container for the Zend_Acl object.
     *
     * @var object
     */
    private $_acl = null;
    
    /**
     * A container for the Zend_Auth object.
     *
     * @var object
     */
    private $_auth = null;
    
    /**
     * A container for the Zend_Auth store.
     * 
     * @var object
     */
    private $_storage = null;
    
    /**
     * A container for Zend_View used to assign user information to the template layer.
     * 
     * @var object Zend_View
     */
    private $_view = null;
    
    /**
     * Container for controlling cycles.
     *
     * @var mixed bool|null
     */
    private $_hasRun = false;
    
    /**
     * Main Access Control List processing action.
     *
     * @param $request Zend_Controller_Request_Abstract           
     *
     * @return void
     */
    public function preDispatch(Zend_Controller_Request_Abstract $request)
    {
        /**
         * Exit object if we have already run.
         */
        if (true === ($this->getHasRun())) {
            return;
        }
        
        /**
         * Defines and creates Access Control List Roles.
         */
        $this->roles();
        
        /**
         * Defines and creates Access Control List Resources.
         */
        $this->resources();
        
        /**
         * Defines and creates Access Control List Access Permissions.
         */
        $this->control();
        
        /**
         * Implements Zend Navigation's Access Control List features.
         */
        $this->setNavigationAcl();
        
        /**
         * Sets the ACL object into the registry to be available system wide.
         */
        $this->setRegistry();
        
        /**
         * Checks access to resources based on defined privileges.
         */
        $this->has();
        
        /**
         * Assigns pertinent Zend_Auth user information to the template layer.
         */
        $this->template();
        
        /**
         * Set hasRun to true.
         */
        $this->setHasRun(true);
    }
    
    /**
     * Sets the _hasRun variable to true. Used to control object cycles.
     */
    private function setHasRun($bool)
    {
        $this->_hasRun = $bool;
    }
    
    /**
     * Returns the hasRun instance.
     * @return bool true/false
     */
    private function getHasRun()
    {
        return $this->_hasRun;
    }
    
    /**
     * Returns parent request object.
     * 
     * (non-PHPdoc)
     * @see Zend_Controller_Plugin_Abstract::getRequest()
     */
    public function getRequest()
    {
        return $this->_request;
    }
    
    /**
     * Gets the Zend_View object from Zend_Layout instance. 
     * Used to assign user information to the view layer.
     */
    public function getView()
    {
        if (null === $this->_view) {
            $this->_view = Zend_Layout::getMvcInstance()->getView();
        }
        return $this->_view;
    }
    
    /**
     * Sets the global ACL registry object.
     */
    public function setRegistry()
    {
        Zend_Registry::getInstance()->set('acl', $this);
        return $this;
    }
    
    /**
     * Returns new Zend_Acl object.
     */
    public function getAcl()
    {
        if (null === $this->_acl) {
            $this->_acl = new Zend_Acl();
        }
        return $this->_acl;
    }
    
    /**
     * Returns a Zend_Auth instance.
     * @return object
     */
    public function getAuth()
    {
        if (null === $this->_auth) {
            $this->_auth = Zend_Auth::getInstance();
        }
        return $this->_auth;
    }
    
    /**
     * Returns Zend_Auth object.
     */
    public function getStorage()
    {
        if (null === $this->_storage) {
            $storage        = $this->getAuth()->getStorage();
            $this->_storage = $storage->read();
        }
        return $this->_storage;
    }
    
    /**
     * Returns the current role in string format.
     *
     * @return string The role name based on the integer provided by Zend_Auth identity.
     */
    public function getRole()
    {
        $roles = array_keys($this->getRoles());
        if (isset($roles[$this->getIdentity()])) {
            return $roles[$this->getIdentity()];
        }
        throw new Zend_Exception('ACL role out of range. Check your identity in the database.');
    }
    
    /**
     * Application roles.
     * 
     * @return array Statically defined user roles.
     */
    public static function getRoles()
    {
        return self::$_roles;
    }
    
    /**
     * Simple returns the Zend_Auth numeric identity.
     *
     * @return mixed int|bool
     */
    public function getIdentity()
    {
        if ($this->getAuth()->hasIdentity()) {
            return $this->getAuth()->getIdentity()->identity;
        }
        return false;
    }
    
    /** 
     * Uses the specified required roles parameter to determine if the current logged in user
     * has acces to specified system resources. This method is to be used to control access to
     * system resources outside of the module/controller/action logic that Zend Acl provides.
     * Returns true if the current role is in the requirement array false otherwise.
     * 
     * if ($acl->hasAllowedRole(array('cfo','ceo','coo'))) {
     *      control logic here.
     * }
     * 
     * @param array $requiredRoles
     * 
     * @return bool
     */
    public function hasAllowedRole($requiredRoles = array())
    {
        /**
         * Checks to see if all of the supplied roles are registered.
         */
        foreach ($requiredRoles as $_index => $role) {
            $this->getAcl()->getRole($role);
        }
        
        if (in_array($this->getRole(), array_values($requiredRoles))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Find the users role name/value in the static roles array.
     *
     * @return static|boolean
     */
    public function getRoleName()
    {
        $roles = $this->getRoles();
        
        $keys = array_keys($roles);
        
        $identity = $this->getIdentity();
        
        if (isset($roles[$keys[$identity]])) {
            return $roles[$keys[$identity]];
        }
        
        return false;
    }
    
    /**
     * Returns the key number based on the role provided.
     *
     * @param string $role
     * @throws Exception
     * @return mixed integer the array key of the role.
     */
    public function getKeyByRole($role)
    {
        try {
            $this->getAcl()->getRole($role);
        } catch (Zend_Acl_Exception $e) {
            throw new Exception('Could not find role ' . $role . '... Are you sure you spelled it right?');
        }
        
        return array_search($role, array_keys($this->getRoles()));
    }
    
    /**
     * Begin encapsulated methods.
     */
    
    /**
     * Assigns user information to the view layer.
     * 
     * @return Plugin_Access_Acl/Zend_Controller_Plugin_Abstract Fluent.
     */
    private function template()
    {
        $this->getView()->auth_role  = $this->getRoleName();
        $this->getView()->auth_id    = (isset($this->getStorage()->id)) ? $this->getStorage()->id : 0;
        $this->getView()->auth_name  = (isset($this->getStorage()->name)) ? $this->getStorage()->name : '';
        $this->getView()->auth_email = (isset($this->getStorage()->email)) ? $this->getStorage()->email : '';
        return $this;
    }
    
    /**
     * Authorization
     *
     * @return Plugin_Access_Acl/Zend_Controller_Plugin_Abstract Fluent.
     */
    private function has()
    {
        $module     = $this->getRequest()->getModuleName();
        $controller = $this->getRequest()->getControllerName();
        $action     = $this->getRequest()->getActionName();
        
        if (!$this->getAcl()->isAllowed($this->getRole(), $module, $controller)) {
            $this->getRequest()->setModuleName('default')->setControllerName('login')->setActionName('index')->setDispatched(false);
        }
        
        return $this;
    }
    
    /**
     * ACL Roles.
     *
     * @return Plugin_Access_Acl/Zend_Controller_Plugin_Abstract Fluent.
     */
    private function roles()
    {
        $this->getAcl()->addRole(new Zend_Acl_Role('anonymous'));
        $this->getAcl()->addRole(new Zend_Acl_Role('member'), 'anonymous');
        $this->getAcl()->addRole(new Zend_Acl_Role('moderator'), 'member');
        $this->getAcl()->addRole(new Zend_Acl_Role('administrator'));
        return $this;
    }
    
    /**
     * ACL Resources.
     *
     * @return Plugin_Access_Acl/Zend_Controller_Plugin_Abstract Fluent.
     */
    private function resources()
    {
        /**
         * Default module.
         */
        $this->getAcl()->add(new Zend_Acl_Resource('default'));
        $this->getAcl()->add(new Zend_Acl_Resource('index'));
        $this->getAcl()->add(new Zend_Acl_Resource('login'));
        $this->getAcl()->add(new Zend_Acl_Resource('logout'));
        $this->getAcl()->add(new Zend_Acl_Resource('register'));
        $this->getAcl()->add(new Zend_Acl_Resource('error'));
        $this->getAcl()->add(new Zend_Acl_Resource('install'));
        $this->getAcl()->add(new Zend_Acl_Resource('account'));
        
        /**
         * Member module.
         */
        $this->getAcl()->add(new Zend_Acl_Resource('member'));
        
        /**
         * Moderator module.
         */
        $this->getAcl()->add(new Zend_Acl_Resource('moderator'));
        
        /**
         * Admin module.
         */
        $this->getAcl()->add(new Zend_Acl_Resource('admin'));
        
        return $this;
    }
    
    /**
     * ACL Control.
     *
     * @return Plugin_Access_Acl/Zend_Controller_Plugin_Abstract Fluent.
     */
    private function control()
    {
        /**
         * Default module/privileges.
         */
        $this->getAcl()->allow('anonymous', 'default');
        $this->getAcl()->allow('anonymous', 'login');
        $this->getAcl()->allow('anonymous', 'logout');
        $this->getAcl()->allow('anonymous', 'register');
        $this->getAcl()->allow('anonymous', 'error');
        /**
         * This should be removed after installation.
         */
        $this->getAcl()->allow('anonymous', 'install');
        
        /**
         * Gives registered members access to the account controller.
         * This resource is defined in a Zend_Naviation container.
         */
        $this->getAcl()->allow('member', 'account');
        
        /**
         * Give registered members access to the member module.
         */
        $this->getAcl()->allow('member', 'member');
        
        /**
         * Give registered moderators access to the moderator module.
         */
        $this->getAcl()->allow('moderator', 'moderator');
        
        /**
         * Allow administrator access to everything.
         */
        $this->getAcl()->allow('administrator');
        
        /**
         * Remove login+register otherwise remove logout.
         */
        if ($this->getAuth()->hasIdentity()) {
            $this->getAcl()->deny($this->getRole(), 'login');
            $this->getAcl()->deny($this->getRole(), 'register');
        } else {
            $this->getAcl()->deny($this->getRole(), 'logout');
        }
        
        return $this;
    }
    
    /**
     * Zend_Navigation.
     *
     * @return Plugin_Access_Acl/Zend_Controller_Plugin_Abstract Fluent.
     */
    private function setNavigationAcl()
    {
        Zend_View_Helper_Navigation_HelperAbstract::setDefaultAcl($this->getAcl());
        Zend_View_Helper_Navigation_HelperAbstract::setDefaultRole($this->getRole());
        return $this;
    }
    
    /**
     * getIterator() - complete the IteratorAggregate interface, for iterating
     *
     * @return ArrayObject
     */
    public function getIterator()
    {
        if ($this->hasRole()) {
            return new ArrayObject($this->getRoles());
        }
        return new ArrayObject();
    }
    
    /**
     * count() - Complete the countable interface
     *
     * @return int
     */
    public function count()
    {
        if ($this->hasRole()) {
            return count($this->getRoles());
        }
        return 0;
    }
}